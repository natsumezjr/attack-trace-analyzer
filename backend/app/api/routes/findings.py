from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.utils import err, ok, utc_now_rfc3339
from app.services.opensearch.internal import INDEX_PATTERNS, get_client


router = APIRouter()


class FindingsSearchRequest(BaseModel):
    stage: Literal["raw", "canonical"] = "canonical"

    start_ts: datetime | None = None
    end_ts: datetime | None = None

    host_id: str | None = None

    tactic_ids: list[str] | None = None
    technique_ids: list[str] | None = None
    rule_ids: list[str] | None = None
    providers: list[str] | None = None

    min_severity: int | None = Field(None, ge=0, le=100)

    # Advanced: pass raw OpenSearch query DSL (the value of "query").
    query: dict[str, Any] | None = None

    size: int = Field(100, ge=1, le=2000)
    offset: int = Field(0, ge=0)
    sort_order: Literal["asc", "desc"] = "desc"


def _iso(dt: datetime) -> str:
    s = dt.isoformat()
    return s.replace("+00:00", "Z")


def _build_query(req: FindingsSearchRequest) -> dict[str, Any]:
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

    if req.tactic_ids:
        filters.append({"terms": {"threat.tactic.id": req.tactic_ids}})
    if req.technique_ids:
        filters.append({"terms": {"threat.technique.id": req.technique_ids}})
    if req.rule_ids:
        filters.append({"terms": {"rule.id": req.rule_ids}})
    if req.providers:
        filters.append({"terms": {"custom.finding.providers": req.providers}})

    if req.min_severity is not None:
        filters.append({"range": {"event.severity": {"gte": req.min_severity}}})

    if not filters:
        return {"match_all": {}}

    return {"bool": {"filter": filters}}


@router.post("/api/v1/findings/search")
def search_findings(req: FindingsSearchRequest):
    if req.stage == "raw":
        index = f"{INDEX_PATTERNS['RAW_FINDINGS']}-*"
    else:
        index = f"{INDEX_PATTERNS['CANONICAL_FINDINGS']}-*"

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
