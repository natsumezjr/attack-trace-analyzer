from __future__ import annotations

import asyncio
import logging
import os
from threading import Lock
from typing import Any

import httpx
from urllib.parse import urlsplit

from app.core.time import utc_now_rfc3339
from app.services.opensearch import run_data_analysis, store_events
from app.services.neo4j.ingest import ingest_from_opensearch
from app.services.opensearch.internal import INDEX_PATTERNS, get_client


_LOGGER = logging.getLogger(__name__)

_stop_event: asyncio.Event | None = None
_poll_task: asyncio.Task[None] | None = None
_last_poll_lock = Lock()
_last_poll_bytes = 0
_last_poll_at: str | None = None


def _set_last_poll_bytes(value: int) -> None:
    global _last_poll_bytes, _last_poll_at
    with _last_poll_lock:
        _last_poll_bytes = value
        _last_poll_at = utc_now_rfc3339()


def get_last_poll_throughput() -> tuple[int, str | None]:
    with _last_poll_lock:
        return _last_poll_bytes, _last_poll_at


def _poll_interval_seconds() -> int:
    raw = os.getenv("CENTER_POLL_INTERVAL_SECONDS", "5").strip()
    try:
        value = int(raw, 10)
    except ValueError:
        value = 5
    return max(1, min(value, 3600))


def _poll_timeout() -> httpx.Timeout:
    raw = os.getenv("CENTER_POLL_TIMEOUT_SECONDS", "5").strip()
    try:
        value = float(raw)
    except ValueError:
        value = 5.0
    return httpx.Timeout(value, connect=min(2.0, value))


def _list_registered_targets(limit: int = 2000) -> list[str]:
    try:
        client = get_client()
        resp = client.search(
            index=INDEX_PATTERNS["CLIENT_REGISTRY"],
            body={
                "query": {"match_all": {}},
                "size": limit,
                "sort": [{"poll.last_seen": {"order": "desc", "unmapped_type": "date"}}],
            },
        )
    except Exception as exc:
        _LOGGER.debug("list clients failed: %s", exc)
        return []

    hits = (resp or {}).get("hits", {}).get("hits", [])
    targets: list[str] = []
    for hit in hits:
        src = hit.get("_source")
        if isinstance(src, dict):
            client_obj = src.get("client") if isinstance(src.get("client"), dict) else {}
            client_id = client_obj.get("id") if isinstance(client_obj.get("id"), str) else None
            if not client_id:
                host_obj = src.get("host") if isinstance(src.get("host"), dict) else {}
                host_id = host_obj.get("id") if isinstance(host_obj.get("id"), str) else None
                host_name = host_obj.get("name") if isinstance(host_obj.get("name"), str) else None
                client_id = host_id or host_name
            if client_id:
                targets.append(client_id)
    return list(dict.fromkeys(targets))


def _poll_url(target_ip: str, route: str) -> str:
    raw = target_ip.strip()
    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or parts.netloc
    else:
        host = raw
    if not host:
        host = raw
    host = host.split("/")[0].split(":")[0]
    return f"http://{host}:8888/{route.lstrip('/')}"


def _update_poll_status(client_id: str, *, status: str, last_error: str | None) -> None:
    now = utc_now_rfc3339()
    try:
        client = get_client()
        client.update(
            index=INDEX_PATTERNS["CLIENT_REGISTRY"],
            id=client_id,
            body={
                "doc": {
                    "poll.last_seen": now,
                    "poll.status": status,
                    "poll.last_error": last_error,
                }
            },
        )
    except Exception as exc:
        _LOGGER.debug("update poll status failed (%s): %s", client_id, exc)


async def _fetch_events(http: httpx.AsyncClient, url: str) -> tuple[list[dict[str, Any]], int]:
    resp = await http.get(url)
    _LOGGER.info(
        "poll response url=%s status=%s headers=%s body=%s",
        url,
        resp.status_code,
        dict(resp.headers),
        resp.text,
    )
    resp.raise_for_status()
    payload_size = len(resp.content or b"")
    payload = resp.json()
    if not isinstance(payload, dict):
        return [], payload_size
    data = payload.get("data")
    if not isinstance(data, list):
        return [], payload_size
    return [item for item in data if isinstance(item, dict)], payload_size


async def _poll_client(http: httpx.AsyncClient, target_ip: str) -> tuple[list[dict[str, Any]], int]:
    routes = ["falco", "suricata", "filebeat"]

    all_events: list[dict[str, Any]] = []
    last_error: str | None = None
    ok_routes: list[str] = []
    failed_routes: list[str] = []
    total_bytes = 0
    for route in routes:
        url = _poll_url(target_ip, route)
        _LOGGER.info("poll request ip=%s url=%s", target_ip, url)
        try:
            events, payload_size = await _fetch_events(http, url)
            total_bytes += payload_size
            all_events.extend(events)
            ok_routes.append(route)
            _LOGGER.info("poll ok ip=%s route=%s bytes=%s", target_ip, route, payload_size)
        except Exception as exc:
            last_error = f"{route}: {exc}"
            _LOGGER.exception(
                "poll failed ip=%s route=%s url=%s error_type=%s error=%s",
                target_ip,
                route,
                url,
                type(exc).__name__,
                repr(exc),
            )
            failed_routes.append(route)
            _LOGGER.warning("poll failed ip=%s route=%s error=%s", target_ip, route, exc)
            continue

    if failed_routes and not ok_routes:
        status = "error"
    elif failed_routes:
        status = "partial"
    else:
        status = "ok"
    _update_poll_status(target_ip, status=status, last_error=last_error)
    if status == "ok":
        _LOGGER.info(
            "poll ok ip=%s routes=%s bytes=%s",
            target_ip,
            ",".join(ok_routes),
            total_bytes,
        )
    else:
        _LOGGER.warning(
            "poll %s ip=%s ok=%s failed=%s last_error=%s",
            status,
            target_ip,
            ",".join(ok_routes) or "-",
            ",".join(failed_routes) or "-",
            last_error or "-",
        )
    return all_events, total_bytes


async def _poll_loop(stop_event: asyncio.Event) -> None:
    async with httpx.AsyncClient(timeout=_poll_timeout()) as http:
        while not stop_event.is_set():
            tick_bytes = 0
            tick_events: list[dict[str, Any]] = []
            for target_ip in _list_registered_targets():
                if not target_ip:
                    continue
                try:
                    events, total_bytes = await _poll_client(http, target_ip)
                    if events:
                        tick_events.extend(events)
                    tick_bytes += total_bytes
                except httpx.TimeoutException:
                    _update_poll_status(target_ip, status="timeout", last_error="timeout")
                except Exception as exc:
                    _update_poll_status(target_ip, status="error", last_error=str(exc))
            _set_last_poll_bytes(tick_bytes)
            if tick_events:
                _LOGGER.info("poll tick store events count=%s", len(tick_events))
                store_result = await asyncio.to_thread(store_events, tick_events)
                _LOGGER.info("poll tick store events done result=%s", store_result)
                analysis_result = await asyncio.to_thread(run_data_analysis, True, False)
                _LOGGER.info("poll tick analysis done result=%s", analysis_result)
                total_events, node_count, edge_count = await asyncio.to_thread(ingest_from_opensearch)
                _LOGGER.info(
                    "poll tick ingest done events=%s nodes=%s edges=%s",
                    total_events,
                    node_count,
                    edge_count,
                )
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=_poll_interval_seconds())
            except asyncio.TimeoutError:
                continue


async def start_polling() -> None:
    global _stop_event, _poll_task
    if _poll_task and not _poll_task.done():
        return
    _stop_event = asyncio.Event()
    _poll_task = asyncio.create_task(_poll_loop(_stop_event))


async def stop_polling() -> None:
    global _stop_event, _poll_task
    if _stop_event is None or _poll_task is None:
        return
    _stop_event.set()
    try:
        await _poll_task
    except asyncio.CancelledError:
        pass
    finally:
        _stop_event = None
        _poll_task = None
