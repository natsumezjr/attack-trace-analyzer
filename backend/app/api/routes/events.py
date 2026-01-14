from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.utils import err, ok, utc_now_rfc3339
from app.services.opensearch.internal import INDEX_PATTERNS, get_client


router = APIRouter()


class EventsSearchRequest(BaseModel):
    start_ts: datetime | None = None
    end_ts: datetime | None = None

    host_id: str | None = None
    host_name: str | None = None

    event_ids: list[str] | None = None
    datasets: list[str] | None = None

    # Advanced: pass raw OpenSearch query DSL (the value of "query").
    query: dict[str, Any] | None = None

    size: int = Field(100, ge=1, le=2000)
    offset: int = Field(0, ge=0)
    sort_order: Literal["asc", "desc"] = "desc"


def _iso(dt: datetime) -> str:
    # OpenSearch accepts ISO 8601 timestamps.
    s = dt.isoformat()
    return s.replace("+00:00", "Z")


def _wildcard_or_term(field: str, value: str) -> dict[str, Any]:
    if "*" in value or "?" in value:
        return {"wildcard": {field: {"value": value}}}
    return {"term": {field: value}}


def _build_query(req: EventsSearchRequest) -> dict[str, Any]:
    if isinstance(req.query, dict) and req.query:
        return req.query

    filters: list[dict[str, Any]] = []

    if req.start_ts or req.end_ts:
        time_range: dict[str, Any] = {}
        if req.start_ts:
            time_range["gte"] = _iso(req.start_ts)
        if req.end_ts:
            time_range["lte"] = _iso(req.end_ts)
        filters.append({"range": {"@timestamp": time_range}})

    if req.host_id:
        filters.append({"term": {"host.id": req.host_id}})
    if req.host_name:
        filters.append({"term": {"host.name": req.host_name}})

    if req.event_ids:
        filters.append({"terms": {"event.id": req.event_ids}})

    if req.datasets:
        should = [_wildcard_or_term("event.dataset", v) for v in req.datasets if v]
        if should:
            filters.append({"bool": {"should": should, "minimum_should_match": 1}})

    if not filters:
        return {"match_all": {}}

    return {"bool": {"filter": filters}}


@router.post("/api/v1/events/search")
def search_events(req: EventsSearchRequest):
    index = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    query = _build_query(req)

    try:
        client = get_client()
        resp = client.search(
            index=index,
            body={
                "track_total_hits": True,
                "query": query,
                "from": req.offset,
                "size": req.size,
                "sort": [{"@timestamp": {"order": req.sort_order}}],
            },
        )
    except Exception as error:
        # Usually OpenSearch connectivity / auth problems.
        return JSONResponse(
            status_code=503,
            content=err("OPENSEARCH_UNAVAILABLE", str(error)),
        )

    hits = (resp or {}).get("hits", {})
    raw_total = hits.get("total", 0)
    total = raw_total.get("value", 0) if isinstance(raw_total, dict) else int(raw_total or 0)
    items = [h.get("_source") for h in hits.get("hits", []) if isinstance(h.get("_source"), dict)]

    return ok(
        total=total,
        items=items,
        server_time=utc_now_rfc3339(),
    )
