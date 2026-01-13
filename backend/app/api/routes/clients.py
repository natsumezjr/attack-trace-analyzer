from __future__ import annotations

import base64
import hashlib
import hmac
import os
from threading import RLock
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.utils import err, ok, utc_now_rfc3339
from app.services.opensearch.client import ensure_index, get_client
from app.services.opensearch.index import INDEX_PATTERNS, hash_token
from app.services.opensearch.mappings import client_registry_mapping


router = APIRouter()

_INMEM_REGISTRY: dict[str, dict[str, Any]] = {}
_INMEM_LOCK = RLock()


def _client_registry_index() -> str:
    return INDEX_PATTERNS["CLIENT_REGISTRY"]


def _poll_interval_seconds() -> int:
    raw = os.getenv("CENTER_POLL_INTERVAL_SECONDS", "").strip()
    if not raw:
        return 5
    try:
        value = int(raw, 10)
    except ValueError:
        return 5
    return max(1, min(value, 3600))


def _token_secret() -> bytes:
    # v1/MVP: allow a default secret to reduce setup friction.
    # TODO: require an explicit secret for production deployments.
    secret = os.getenv("CENTER_CLIENT_TOKEN_SECRET", "dev-insecure-secret-change-me").encode(
        "utf-8"
    )
    return secret


def _generate_client_token(client_id: str) -> str:
    digest = hmac.new(_token_secret(), client_id.encode("utf-8"), hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"ata_{token}"


class RegisterHost(BaseModel):
    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)


class RegisterCapabilities(BaseModel):
    filebeat: bool
    falco: bool
    suricata: bool


class RegisterClientRequest(BaseModel):
    client_id: str = Field(..., min_length=1)
    client_version: str = Field(..., min_length=1)
    listen_url: str = Field(..., min_length=1)
    host: RegisterHost
    capabilities: RegisterCapabilities


def _validate_register_request(req: RegisterClientRequest) -> str | None:
    if not (req.listen_url.startswith("http://") or req.listen_url.startswith("https://")):
        return "listen_url must start with http:// or https://"
    return None


def _as_client_item(doc: dict[str, Any]) -> dict[str, Any]:
    client = doc.get("client") if isinstance(doc.get("client"), dict) else {}
    poll = doc.get("poll") if isinstance(doc.get("poll"), dict) else {}
    return {
        "client_id": client.get("id"),
        "listen_url": client.get("listen_url"),
        "client_version": client.get("version"),
        "host": client.get("host") if isinstance(client.get("host"), dict) else {},
        "capabilities": client.get("capabilities")
        if isinstance(client.get("capabilities"), dict)
        else {},
        "poll": {
            "cursor": poll.get("cursor"),
            "last_seen": poll.get("last_seen"),
            "last_error": poll.get("last_error"),
            "status": poll.get("status"),
        },
        "registered_at": doc.get("@timestamp"),
    }


@router.post("/api/v1/clients/register")
def register_client(req: RegisterClientRequest):
    validation_error = _validate_register_request(req)
    if validation_error:
        return JSONResponse(
            status_code=400,
            content=err("BAD_REQUEST", validation_error),
        )

    token = _generate_client_token(req.client_id)
    token_hash = hash_token(token)
    now = utc_now_rfc3339()

    doc: dict[str, Any] = {
        "@timestamp": now,
        "client": {
            "id": req.client_id,
            "listen_url": req.listen_url,
            "version": req.client_version,
            "host": {"id": req.host.id, "name": req.host.name},
            "capabilities": {
                "filebeat": req.capabilities.filebeat,
                "falco": req.capabilities.falco,
                "suricata": req.capabilities.suricata,
            },
            "token_hash": token_hash,
        },
        "poll": {
            "cursor": "0",
            "last_seen": now,
            "last_error": None,
            "status": "registered",
        },
    }

    stored = False
    os_error: str | None = None

    try:
        ensure_index(_client_registry_index(), client_registry_mapping)
        client = get_client()

        # Preserve poll cursor if present (idempotent re-register).
        try:
            existing = client.get(index=_client_registry_index(), id=req.client_id)
            existing_src = existing.get("_source", {}) if isinstance(existing, dict) else {}
            existing_poll = (
                existing_src.get("poll") if isinstance(existing_src.get("poll"), dict) else {}
            )
            existing_cursor = existing_poll.get("cursor")
            if isinstance(existing_cursor, str) and existing_cursor:
                doc["poll"]["cursor"] = existing_cursor
        except Exception:
            pass

        client.index(index=_client_registry_index(), id=req.client_id, body=doc)
        stored = True
    except Exception as error:
        os_error = str(error)

    if not stored:
        # Best-effort fallback to in-memory registry.
        with _INMEM_LOCK:
            existing = _INMEM_REGISTRY.get(req.client_id)
            if isinstance(existing, dict):
                existing_poll = existing.get("poll") if isinstance(existing.get("poll"), dict) else {}
                existing_cursor = existing_poll.get("cursor")
                if isinstance(existing_cursor, str) and existing_cursor:
                    doc["poll"]["cursor"] = existing_cursor
            _INMEM_REGISTRY[req.client_id] = doc

    res = ok(
        client_token=token,
        poll_interval_seconds=_poll_interval_seconds(),
        server_time=now,
    )

    if os_error is not None and not stored:
        # Surface storage failure to the caller without failing registration.
        # TODO: decide whether registration should hard-fail when OpenSearch is down.
        res["warning"] = f"client registry stored in-memory only (opensearch error: {os_error})"

    return res


@router.get("/api/v1/clients")
def list_clients(limit: int = 200):
    limit = max(1, min(int(limit), 2000))

    docs: list[dict[str, Any]] = []
    try:
        client = get_client()
        resp = client.search(
            index=_client_registry_index(),
            body={
                "query": {"match_all": {}},
                "size": limit,
                "sort": [
                    {"poll.last_seen": {"order": "desc", "unmapped_type": "date"}},
                    {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
                ],
            },
        )
        hits = (resp or {}).get("hits", {}).get("hits", [])
        for hit in hits:
            src = hit.get("_source")
            if isinstance(src, dict):
                docs.append(src)
    except Exception:
        with _INMEM_LOCK:
            docs = list(_INMEM_REGISTRY.values())[:limit]

    return ok(
        clients=[_as_client_item(d) for d in docs],
        server_time=utc_now_rfc3339(),
    )
