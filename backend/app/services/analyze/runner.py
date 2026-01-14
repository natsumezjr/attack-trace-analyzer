from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.time import format_rfc3339, utc_now
from app.services.analyze.pipeline import run_analysis_task
from app.services.opensearch.client import ensure_index, index_document
from app.services.opensearch.index import INDEX_PATTERNS, get_index_name
from app.services.opensearch.mappings import analysis_tasks_mapping


_LOGGER = logging.getLogger(__name__)

_stop_event: asyncio.Event | None = None
_runner_task: asyncio.Task[None] | None = None
_queue: asyncio.Queue["AnalysisTaskSpec"] | None = None


@dataclass(frozen=True)
class AnalysisTaskSpec:
    task_id: str
    target_node_uid: str
    start_ts: datetime
    end_ts: datetime
    created_at: datetime


def _ensure_task_index(created_at: datetime) -> str:
    index_name = get_index_name(INDEX_PATTERNS["ANALYSIS_TASKS"], created_at)
    ensure_index(index_name, analysis_tasks_mapping)
    return index_name


def _write_task_doc(index_name: str, *, task_id: str, doc: dict[str, Any]) -> None:
    # Keep OpenSearch document id stable for polling.
    index_document(index_name, doc, doc_id=task_id)


async def enqueue_analysis_task(
    *,
    task_id: str,
    target_node_uid: str,
    start_ts: datetime,
    end_ts: datetime,
    created_at: datetime | None = None,
) -> None:
    """
    Enqueue an analysis task for async execution (in-process runner).

    This function also creates the initial OpenSearch task document so that the
    frontend can poll immediately after receiving task_id.
    """
    if _queue is None:
        raise RuntimeError("analysis runner is not started")

    created_at_dt = created_at or utc_now()
    index_name = await asyncio.to_thread(_ensure_task_index, created_at_dt)

    queued_doc: dict[str, Any] = {
        "@timestamp": format_rfc3339(created_at_dt),
        "task.id": task_id,
        "task.status": "queued",
        "task.progress": 0,
        "task.target.node_uid": target_node_uid,
        "task.window.start_ts": format_rfc3339(start_ts),
        "task.window.end_ts": format_rfc3339(end_ts),
    }
    await asyncio.to_thread(_write_task_doc, index_name, task_id=task_id, doc=queued_doc)

    _queue.put_nowait(
        AnalysisTaskSpec(
            task_id=task_id,
            target_node_uid=target_node_uid,
            start_ts=start_ts,
            end_ts=end_ts,
            created_at=created_at_dt,
        )
    )


async def _run_once(spec: AnalysisTaskSpec) -> None:
    try:
        await run_analysis_task(
            task_id=spec.task_id,
            target_node_uid=spec.target_node_uid,
            start_ts=spec.start_ts,
            end_ts=spec.end_ts,
            created_at=spec.created_at,
        )
    except Exception as exc:
        # run_analysis_task already writes "failed" to OpenSearch; we just log.
        _LOGGER.exception("analysis task failed (%s): %s", spec.task_id, exc)


async def _runner_loop(stop_event: asyncio.Event) -> None:
    assert _queue is not None
    while not stop_event.is_set():
        try:
            spec = await asyncio.wait_for(_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        try:
            await _run_once(spec)
        finally:
            _queue.task_done()


async def start_task_runner() -> None:
    global _stop_event, _runner_task, _queue
    if _runner_task and not _runner_task.done():
        return
    _stop_event = asyncio.Event()
    _queue = asyncio.Queue()
    _runner_task = asyncio.create_task(_runner_loop(_stop_event))


async def stop_task_runner() -> None:
    global _stop_event, _runner_task, _queue
    if _stop_event is None or _runner_task is None:
        return
    _stop_event.set()
    try:
        await _runner_task
    except asyncio.CancelledError:
        pass
    finally:
        _stop_event = None
        _runner_task = None
        _queue = None

