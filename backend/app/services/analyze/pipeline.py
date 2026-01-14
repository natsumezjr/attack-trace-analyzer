from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.time import format_rfc3339, parse_datetime, utc_now, utc_now_rfc3339
from app.services.analyze.trace import TraceResult, compute_trace
from app.services.analyze.ttp_similarity.service import (
    fetch_attack_ttps_from_canonical_findings,
    rank_similar_intrusion_sets,
)
from app.services.neo4j import internal as graph_api
from app.services.opensearch.client import ensure_index, index_document
from app.services.opensearch.index import INDEX_PATTERNS, get_index_name
from app.services.opensearch.mappings import analysis_tasks_mapping


_TASK_ID_RE = re.compile(r"^trace-[0-9a-fA-F-]{36}$")


def new_task_id() -> str:
    """Generate a globally unique task id following docs/33 convention."""
    return f"trace-{uuid.uuid4()}"


@dataclass(frozen=True)
class TtpSimilarityResult:
    attack_tactics: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    similar_apts: list[dict[str, Any]]


@dataclass(frozen=True)
class AnalysisPipelineResult:
    task_id: str
    trace: TraceResult
    ttp_similarity: TtpSimilarityResult
    updated_edges: int


def _ensure_analysis_tasks_index(created_at: datetime) -> str:
    index_name = get_index_name(INDEX_PATTERNS["ANALYSIS_TASKS"], created_at)
    ensure_index(index_name, analysis_tasks_mapping)
    return index_name


def _write_task_doc(index_name: str, *, task_id: str, doc: dict[str, Any]) -> None:
    # Keep a stable OpenSearch document ID = task_id.
    index_document(index_name, doc, doc_id=task_id)


def _infer_host_id_from_node_uid(target_node_uid: str) -> str:
    """
    Best-effort host.id inference for task-level APT similarity.

    - Prefer host.id from the target node (Host/User/Process/File nodes).
    - Otherwise, scan 1-hop neighbor nodes and use the first host.id found.
    """
    node = graph_api.get_node(target_node_uid)
    if node is None:
        raise ValueError(f"target node not found in neo4j: {target_node_uid}")

    # Direct host.id on node
    host_id = None
    if isinstance(node.key, dict):
        host_id = node.key.get("host.id")
    if not host_id and isinstance(node.props, dict):
        host_id = node.props.get("host.id")
    if isinstance(host_id, str) and host_id:
        return host_id

    # 1-hop neighbor scan
    for edge in graph_api.get_edges(node):
        for uid in (edge.src_uid, edge.dst_uid):
            neighbor = graph_api.get_node(uid)
            if neighbor is None:
                continue
            hid = None
            if isinstance(neighbor.key, dict):
                hid = neighbor.key.get("host.id")
            if not hid and isinstance(neighbor.props, dict):
                hid = neighbor.props.get("host.id")
            if isinstance(hid, str) and hid:
                return hid

    raise ValueError(f"cannot infer host.id from target node uid: {target_node_uid}")


def _compute_ttp_similarity(*, host_id: str, start_ts: datetime, end_ts: datetime) -> TtpSimilarityResult:
    attack_tactics, attack_techniques = fetch_attack_ttps_from_canonical_findings(
        host_id=host_id,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    attack_ids, candidates = rank_similar_intrusion_sets(
        attack_tactics=attack_tactics,
        attack_techniques=attack_techniques,
    )

    return TtpSimilarityResult(
        attack_tactics=tuple(sorted(attack_tactics)),
        attack_techniques=tuple(attack_ids),
        similar_apts=[
            {
                "intrusion_set": {"id": c.intrusion_set_id, "name": c.intrusion_set_name},
                "similarity_score": c.similarity_score,
                "top_tactics": list(c.top_tactics),
                "top_techniques": list(c.top_techniques),
            }
            for c in candidates
        ],
    )


def _validate_task_id(task_id: str) -> None:
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("task_id is required")
    if not _TASK_ID_RE.match(task_id):
        raise ValueError("invalid task_id format (expected trace-<uuid_v4>)")


async def run_analysis_task(
    *,
    task_id: str,
    target_node_uid: str,
    start_ts: datetime | str,
    end_ts: datetime | str,
) -> AnalysisPipelineResult:
    """
    Main analysis entry point (task-driven).

    Inputs:
    - task_id: trace-<uuid_v4>
    - target_node_uid + time window

    Outputs (all mandatory):
    1) Task-level APT similarity result (OpenSearch task document)
    2) Trace edges + key path marking (Neo4j edge properties)
    3) Derived edge-level technique ids on path edges (Neo4j edge properties)

    NOTE: This function is async and offloads blocking DB/OS calls to threads.
    """
    _validate_task_id(task_id)

    start_dt = parse_datetime(start_ts)
    end_dt = parse_datetime(end_ts)
    if start_dt is None or end_dt is None:
        raise ValueError("start_ts and end_ts must be valid datetimes")
    if end_dt < start_dt:
        raise ValueError("end_ts must be >= start_ts")

    created_at_dt = utc_now()
    created_at = format_rfc3339(created_at_dt)
    index_name = await asyncio.to_thread(_ensure_analysis_tasks_index, created_at_dt)

    # 1) Create task doc (queued)
    task_doc: dict[str, Any] = {
        "@timestamp": created_at,
        "task.id": task_id,
        "task.status": "queued",
        "task.progress": 0,
        "task.target.node_uid": target_node_uid,
        "task.window.start_ts": format_rfc3339(start_dt),
        "task.window.end_ts": format_rfc3339(end_dt),
    }
    await asyncio.to_thread(_write_task_doc, index_name, task_id=task_id, doc=task_doc)

    started_at = utc_now_rfc3339()
    task_doc.update(
        {
            "task.status": "running",
            "task.progress": 5,
            "task.started_at": started_at,
        }
    )
    await asyncio.to_thread(_write_task_doc, index_name, task_id=task_id, doc=task_doc)

    try:
        # Inputs for the 2 main algorithms
        host_id = await asyncio.to_thread(_infer_host_id_from_node_uid, target_node_uid)

        # 2 main algorithms in parallel:
        # - Trace/backtracking (Neo4j)
        # - APT similarity (OpenSearch + offline CTI)
        trace_task = asyncio.to_thread(
            compute_trace,
            task_id=task_id,
            target_node_uid=target_node_uid,
            start_ts=start_dt,
            end_ts=end_dt,
        )
        ttp_task = asyncio.to_thread(
            _compute_ttp_similarity,
            host_id=host_id,
            start_ts=start_dt,
            end_ts=end_dt,
        )

        task_doc["task.progress"] = 20
        await asyncio.to_thread(_write_task_doc, index_name, task_id=task_id, doc=task_doc)

        trace_result, ttp_result = await asyncio.gather(trace_task, ttp_task)

        task_doc["task.progress"] = 70
        task_doc["task.result.ttp_similarity.attack_tactics"] = list(ttp_result.attack_tactics)
        task_doc["task.result.ttp_similarity.attack_techniques"] = list(ttp_result.attack_techniques)
        task_doc["task.result.ttp_similarity.similar_apts"] = ttp_result.similar_apts
        await asyncio.to_thread(_write_task_doc, index_name, task_id=task_id, doc=task_doc)

        # Write trace result back to Neo4j (analysis.* fields on edges).
        updated_at = utc_now_rfc3339()
        updated_edges = await asyncio.to_thread(
            graph_api.write_analysis_results,
            trace_result.edges,
            task_id=task_id,
            updated_at=updated_at,
        )

        task_doc["task.progress"] = 95
        task_doc["task.result.trace.updated_edges"] = int(updated_edges)
        task_doc["task.result.trace.path_edges"] = int(trace_result.path_edge_count)

        summary = (
            f"host_id={host_id}; "
            f"trace_edges={len(trace_result.edges)}; "
            f"path_edges={trace_result.path_edge_count}; "
            f"similar_apts={len(ttp_result.similar_apts)}"
        )
        task_doc["task.result.summary"] = summary

        finished_at = utc_now_rfc3339()
        task_doc["task.status"] = "succeeded"
        task_doc["task.progress"] = 100
        task_doc["task.finished_at"] = finished_at
        await asyncio.to_thread(_write_task_doc, index_name, task_id=task_id, doc=task_doc)

        return AnalysisPipelineResult(
            task_id=task_id,
            trace=trace_result,
            ttp_similarity=ttp_result,
            updated_edges=int(updated_edges),
        )

    except Exception as error:
        finished_at = utc_now_rfc3339()
        task_doc["task.status"] = "failed"
        task_doc["task.progress"] = int(task_doc.get("task.progress") or 0)
        task_doc["task.finished_at"] = finished_at
        task_doc["task.error"] = str(error)
        await asyncio.to_thread(_write_task_doc, index_name, task_id=task_id, doc=task_doc)
        raise

