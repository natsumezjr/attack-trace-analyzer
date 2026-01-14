from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.utils import err, ok, utc_now, utc_now_rfc3339
from app.core.time import format_rfc3339, parse_datetime
from app.services.analyze.pipeline import new_task_id
from app.services.analyze.runner import enqueue_analysis_task
from app.services.opensearch.internal import get_client


router = APIRouter()


class CreateAnalysisTaskRequest(BaseModel):
    target_node_uid: str = Field(..., description="Target graph node uid (e.g. Host:host.id=...)")
    start_ts: datetime = Field(..., description="ISO 8601 start timestamp (inclusive)")
    end_ts: datetime = Field(..., description="ISO 8601 end timestamp (inclusive)")


@router.post("/api/v1/analysis/tasks")
async def create_analysis_task(req: CreateAnalysisTaskRequest):
    if req.end_ts < req.start_ts:
        return JSONResponse(
            status_code=400,
            content=err("BAD_REQUEST", "end_ts must be >= start_ts"),
        )

    task_id = new_task_id()
    created_at_dt = utc_now()

    try:
        await enqueue_analysis_task(
            task_id=task_id,
            target_node_uid=req.target_node_uid,
            start_ts=req.start_ts,
            end_ts=req.end_ts,
            created_at=created_at_dt,
        )
    except Exception as error:
        return JSONResponse(
            status_code=500,
            content=err("INTERNAL_ERROR", f"enqueue analysis task failed: {error}"),
        )

    return ok(
        task_id=task_id,
        task={
            "@timestamp": format_rfc3339(created_at_dt),
            "task.id": task_id,
            "task.status": "queued",
            "task.progress": 0,
            "task.target.node_uid": req.target_node_uid,
            "task.window.start_ts": format_rfc3339(req.start_ts),
            "task.window.end_ts": format_rfc3339(req.end_ts),
        },
        server_time=utc_now_rfc3339(),
    )


def _build_task_list_query(
    *,
    status: str | None,
    target_node_uid: str | None,
    created_from: datetime | None,
    created_to: datetime | None,
) -> dict[str, Any]:
    filters: list[dict[str, Any]] = []
    if status:
        filters.append({"term": {"task.status": status}})
    if target_node_uid:
        filters.append({"term": {"task.target.node_uid": target_node_uid}})
    if created_from or created_to:
        time_range: dict[str, Any] = {}
        if created_from:
            time_range["gte"] = format_rfc3339(created_from)
        if created_to:
            time_range["lte"] = format_rfc3339(created_to)
        filters.append({"range": {"@timestamp": time_range}})
    if not filters:
        return {"match_all": {}}
    return {"bool": {"filter": filters}}


@router.get("/api/v1/analysis/tasks")
def list_analysis_tasks(
    status: Literal["queued", "running", "succeeded", "failed"] | None = None,
    target_node_uid: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    size: int = Query(50, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    query = _build_task_list_query(
        status=status,
        target_node_uid=target_node_uid,
        created_from=created_from,
        created_to=created_to,
    )

    try:
        client = get_client()
        resp = client.search(
            index="analysis-tasks-*",
            body={
                "track_total_hits": True,
                "query": query,
                "from": offset,
                "size": size,
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            },
        )
    except Exception as error:
        return JSONResponse(
            status_code=503,
            content=err("OPENSEARCH_UNAVAILABLE", str(error)),
        )

    hits = (resp or {}).get("hits", {})
    raw_total = hits.get("total", 0)
    total = raw_total.get("value", 0) if isinstance(raw_total, dict) else int(raw_total or 0)

    items: list[dict[str, Any]] = []
    for hit in hits.get("hits", []):
        src = hit.get("_source")
        if isinstance(src, dict):
            items.append(src)

    return ok(total=total, items=items, server_time=utc_now_rfc3339())


def _find_task_doc(task_id: str) -> dict[str, Any] | None:
    client = get_client()
    resp = client.search(
        index="analysis-tasks-*",
        body={
            "query": {"term": {"task.id": task_id}},
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        },
    )
    hits = (resp or {}).get("hits", {}).get("hits", [])
    for hit in hits:
        src = hit.get("_source")
        if isinstance(src, dict):
            return src
    return None


@router.get("/api/v1/analysis/tasks/{task_id}")
def get_analysis_task(task_id: str):
    if not isinstance(task_id, str) or not task_id:
        return JSONResponse(
            status_code=400,
            content=err("BAD_REQUEST", "task_id is required"),
        )

    try:
        doc = _find_task_doc(task_id)
    except Exception as error:
        return JSONResponse(
            status_code=503,
            content=err("OPENSEARCH_UNAVAILABLE", str(error)),
        )

    if doc is None:
        return JSONResponse(
            status_code=404,
            content=err("NOT_FOUND", f"analysis task not found: {task_id}"),
        )

    # Normalize timestamps in response (best-effort).
    for k in ("@timestamp", "task.window.start_ts", "task.window.end_ts", "task.started_at", "task.finished_at"):
        v = doc.get(k)
        if isinstance(v, str):
            dt = parse_datetime(v)
            if dt is not None:
                doc[k] = format_rfc3339(dt)

    return ok(task=doc, server_time=utc_now_rfc3339())

