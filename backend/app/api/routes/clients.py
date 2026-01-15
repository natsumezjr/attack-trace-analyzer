from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.utils import err, ok, utc_now_rfc3339
from app.services.opensearch.client import ensure_index, index_document
from app.services.opensearch.internal import INDEX_PATTERNS, get_client
from app.services.opensearch.index import hash_token
from app.services.opensearch.mappings import client_registry_mapping


router = APIRouter()


def _poll_interval_seconds() -> int:
    raw = os.getenv("CENTER_POLL_INTERVAL_SECONDS", "5").strip()
    try:
        value = int(raw, 10)
    except ValueError:
        value = 5
    return max(1, min(value, 3600))


def _validate_listen_url(listen_url: str) -> bool:
    # Keep this intentionally permissive: allow IP-based URLs.
    url = (listen_url or "").strip()
    return url.startswith("http://") or url.startswith("https://")


class ClientHost(BaseModel):
    id: str = Field(..., description="ECS host.id (stable)")
    name: str = Field(..., description="ECS host.name (stable)")


class ClientCapabilities(BaseModel):
    filebeat: bool = True
    falco: bool = True
    suricata: bool = True


class RegisterClientRequest(BaseModel):
    client_id: str = Field(..., description="Stable client identifier")
    client_version: str = Field(..., description="Client version string")
    listen_url: str = Field(..., description="Client listen base URL, e.g. http://10.0.0.11:8888")
    host: ClientHost
    capabilities: ClientCapabilities


@router.post("/api/v1/clients/register")
def register_client(req: RegisterClientRequest):
    if not _validate_listen_url(req.listen_url):
        return JSONResponse(
            status_code=400,
            content=err("BAD_REQUEST", "listen_url must start with http:// or https://"),
        )

    now = utc_now_rfc3339()
    token = f"ata_{uuid.uuid4().hex}"

    # Ensure the fixed registry index exists.
    try:
        ensure_index(INDEX_PATTERNS["CLIENT_REGISTRY"], client_registry_mapping)
    except Exception as error:
        return JSONResponse(
            status_code=503,
            content=err("OPENSEARCH_UNAVAILABLE", str(error)),
        )

    # NOTE: Use document id = client_id for stable updates by poller.
    doc: dict[str, Any] = {
        "@timestamp": now,
        "client": {
            "id": req.client_id,
            "version": req.client_version,
            "token_hash": hash_token(token),
            "listen_url": req.listen_url,
            "capabilities": {
                "filebeat": bool(req.capabilities.filebeat),
                "falco": bool(req.capabilities.falco),
                "suricata": bool(req.capabilities.suricata),
            },
        },
        "host": {"id": req.host.id, "name": req.host.name},
        "poll": {
            "last_seen": now,
            "status": "registered",
            "last_error": None,
        },
    }

    try:
        index_document(INDEX_PATTERNS["CLIENT_REGISTRY"], doc, doc_id=req.client_id)
    except Exception as error:
        return JSONResponse(
            status_code=503,
            content=err("OPENSEARCH_UNAVAILABLE", str(error)),
        )

    return ok(
        client_token=token,
        poll_interval_seconds=_poll_interval_seconds(),
        server_time=now,
    )


@router.get("/api/v1/clients")
def list_clients(size: int = 2000):
    # Small helper endpoint for dashboards/scripts; the poller reads directly from OpenSearch.
    try:
        client = get_client()
        resp = client.search(
            index=INDEX_PATTERNS["CLIENT_REGISTRY"],
            body={
                "track_total_hits": True,
                "query": {"match_all": {}},
                "size": size,
                "sort": [{"poll.last_seen": {"order": "desc", "unmapped_type": "date"}}],
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
