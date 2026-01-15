from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.api.utils import err, ok, utc_now_rfc3339
from app.dto.targets import RegisterTargetRequest
from app.services.client_poller import get_last_poll_throughput
from app.services.opensearch.client import ensure_index, index_document
from app.services.opensearch.internal import INDEX_PATTERNS, get_client
from app.services.opensearch.mappings import client_registry_mapping


router = APIRouter()


@router.post("/api/v1/targets/register")
def register_online_target(req: RegisterTargetRequest):
    # 简化版注册：只提供 IP，由中心机推导 listen_url 与 capabilities，并写入 OpenSearch client-registry。
    ip_str = str(req.ip)

    now = utc_now_rfc3339()
    doc = {
        "@timestamp": now,
        "client": {
            "id": ip_str,
            "version": "manual",
            "listen_url": f"http://{ip_str}:8888",
            "capabilities": {"falco": True, "suricata": True, "filebeat": True},
        },
        "host": {"id": ip_str, "name": ip_str},
        "poll": {"last_seen": now, "status": "registered", "last_error": None},
    }

    try:
        ensure_index(INDEX_PATTERNS["CLIENT_REGISTRY"], client_registry_mapping)
        index_document(INDEX_PATTERNS["CLIENT_REGISTRY"], doc, doc_id=ip_str)
    except Exception as error:
        return JSONResponse(
            status_code=503,
            content=err("OPENSEARCH_UNAVAILABLE", str(error)),
        )

    return ok(ip=ip_str, server_time=now)


@router.get("/api/v1/targets")
def list_online_targets():
    try:
        client = get_client()
        resp = client.search(
            index=INDEX_PATTERNS["CLIENT_REGISTRY"],
            body={
                "query": {"match_all": {}},
                "size": 2000,
                "sort": [{"poll.last_seen": {"order": "desc", "unmapped_type": "date"}}],
            },
        )
    except Exception as error:
        return JSONResponse(
            status_code=503,
            content=err("OPENSEARCH_UNAVAILABLE", str(error)),
        )

    hits = (resp or {}).get("hits", {}).get("hits", [])
    targets: list[str] = []
    for hit in hits:
        src = hit.get("_source")
        if not isinstance(src, dict):
            continue
        client_obj = src.get("client")
        if not isinstance(client_obj, dict):
            continue
        cid = client_obj.get("id")
        if isinstance(cid, str) and cid:
            targets.append(cid)

    return ok(targets=targets, server_time=utc_now_rfc3339())


@router.get("/api/v1/targets/throughput")
def get_poll_throughput():
    throughput_bytes, last_poll_time = get_last_poll_throughput()
    return ok(
        throughput_bytes=throughput_bytes,
        last_poll_time=last_poll_time,
        server_time=utc_now_rfc3339(),
    )
