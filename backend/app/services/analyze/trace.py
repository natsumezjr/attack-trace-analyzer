from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from app.core.time import parse_datetime
from app.services.neo4j import internal as graph_api
from app.services.neo4j.models import GraphEdge, GraphNode


@dataclass(frozen=True)
class TraceResult:
    edges: list[GraphEdge]
    path_edge_count: int


def _as_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _edge_ts_float(edge: GraphEdge) -> float:
    # Prefer ts_float (ingest guarantees best-effort), otherwise fall back to @timestamp/ts.
    tsf = _as_float(edge.props.get("ts_float")) if isinstance(edge.props, dict) else None
    if tsf is not None:
        return tsf
    dt = parse_datetime(edge.get_ts())
    return float(dt.timestamp()) if dt is not None else 0.0


def _in_window(edge: GraphEdge, *, t_min: float, t_max: float) -> bool:
    tsf = _edge_ts_float(edge)
    return t_min <= tsf <= t_max


def _extract_technique_ids(edge: GraphEdge) -> list[str]:
    """
    Derived marking: attach edge-level technique ids for this analysis run.

    Prefer sub-technique then parent technique if both exist.
    """
    if not isinstance(edge.props, dict):
        return []

    out: list[str] = []
    for key in ("threat.technique.subtechnique.id", "threat.technique.id"):
        v = edge.props.get(key)
        if isinstance(v, str) and v and v not in out:
            out.append(v)
    return out


def _derive_risk_score(edge: GraphEdge) -> float:
    """
    Best-effort risk score for path edges.

    This is intentionally simple for now; the detailed risk model belongs to the
    trace algorithm itself.
    """
    if not isinstance(edge.props, dict):
        return 0.0
    sev = edge.props.get("event.severity")
    if isinstance(sev, (int, float)):
        return float(sev)
    return 50.0 if bool(edge.props.get("is_alarm")) else 0.0


def _summarize_edge(edge: GraphEdge) -> str | None:
    if not isinstance(edge.props, dict):
        return None
    parts: list[str] = []
    action = edge.props.get("event.action")
    if isinstance(action, str) and action:
        parts.append(action)
    tactic = edge.props.get("threat.tactic.name")
    if isinstance(tactic, str) and tactic:
        parts.append(f"tactic={tactic}")
    tech = edge.props.get("threat.technique.id")
    if isinstance(tech, str) and tech:
        parts.append(f"tech={tech}")
    if not parts:
        return None
    return " | ".join(parts)


def compute_trace(
    *,
    task_id: str,
    target_node_uid: str,
    start_ts: datetime,
    end_ts: datetime,
) -> TraceResult:
    """
    Trace/backtracking main algorithm (Phase A/B/C...).

    NOTE: For now this implementation focuses on producing a stable pipeline output:
    - Select a subgraph around the target node in the given time window
    - Mark alarm edges as "path edges" (analysis.is_path_edge = true)
    - Attach derived edge-level technique ids (analysis.ttp.technique_ids)
    """
    if end_ts < start_ts:
        raise ValueError("end_ts must be >= start_ts")

    node = graph_api.get_node(target_node_uid)
    if node is None:
        raise ValueError(f"target node not found in neo4j: {target_node_uid}")

    incident = graph_api.get_edges(node)
    t_min = float(start_ts.timestamp())
    t_max = float(end_ts.timestamp())
    edges = [e for e in incident if _in_window(e, t_min=t_min, t_max=t_max)]
    edges.sort(key=_edge_ts_float)

    path_edge_count = 0
    for edge in edges:
        if not isinstance(edge.props, dict):
            continue

        is_path_edge = bool(edge.props.get("is_alarm"))
        edge.props["analysis.task_id"] = task_id
        edge.props["analysis.is_path_edge"] = is_path_edge

        if not is_path_edge:
            continue

        path_edge_count += 1
        edge.props["analysis.risk_score"] = _derive_risk_score(edge)
        edge.props["analysis.ttp.technique_ids"] = _extract_technique_ids(edge)

        summary = _summarize_edge(edge)
        if summary:
            edge.props["analysis.summary"] = summary

    return TraceResult(edges=edges, path_edge_count=path_edge_count)

