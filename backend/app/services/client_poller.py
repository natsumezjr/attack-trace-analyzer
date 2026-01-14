from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

from app.core.time import utc_now_rfc3339
from app.services.opensearch import run_data_analysis, store_events
from app.services.opensearch.internal import INDEX_PATTERNS, get_client


_LOGGER = logging.getLogger(__name__)

_stop_event: asyncio.Event | None = None
_poll_task: asyncio.Task[None] | None = None


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


def _list_registered_clients(limit: int = 2000) -> list[dict[str, Any]]:
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
    docs: list[dict[str, Any]] = []
    for hit in hits:
        src = hit.get("_source")
        if isinstance(src, dict):
            docs.append(src)
    return docs


def _extract_client_info(doc: dict[str, Any]) -> tuple[str | None, str | None, dict[str, bool]]:
    client_obj = doc.get("client") if isinstance(doc.get("client"), dict) else {}
    client_id = client_obj.get("id") if isinstance(client_obj.get("id"), str) else None
    listen_url = (
        client_obj.get("listen_url") if isinstance(client_obj.get("listen_url"), str) else None
    )
    caps_obj = client_obj.get("capabilities") if isinstance(client_obj.get("capabilities"), dict) else {}

    caps = {
        "falco": bool(caps_obj.get("falco")),
        "suricata": bool(caps_obj.get("suricata")),
        "filebeat": bool(caps_obj.get("filebeat")),
    }
    return client_id, listen_url, caps


def _poll_url(listen_url: str, route: str) -> str:
    return f"{listen_url.rstrip('/')}/{route.lstrip('/')}"


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


async def _fetch_events(http: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
    resp = await http.get(url)
    resp.raise_for_status()
    payload = resp.json()
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


async def _poll_client(http: httpx.AsyncClient, client_id: str, listen_url: str, caps: dict[str, bool]) -> None:
    routes = [name for name, enabled in caps.items() if enabled]
    if not routes:
        routes = ["falco", "suricata", "filebeat"]

    all_events: list[dict[str, Any]] = []
    last_error: str | None = None
    for route in routes:
        url = _poll_url(listen_url, route)
        try:
            all_events.extend(await _fetch_events(http, url))
        except Exception as exc:
            last_error = f"{route}: {exc}"
            _LOGGER.debug("poll %s failed: %s", url, exc)
            continue

    if all_events:
        await asyncio.to_thread(store_events, all_events)

    if os.getenv("CENTER_RUN_ANALYSIS_EACH_TICK", "0").strip() in ("1", "true", "yes"):
        await asyncio.to_thread(run_data_analysis, True, False)

    _update_poll_status(client_id, status="ok" if last_error is None else "partial", last_error=last_error)


async def _poll_loop(stop_event: asyncio.Event) -> None:
    async with httpx.AsyncClient(timeout=_poll_timeout()) as http:
        while not stop_event.is_set():
            for doc in _list_registered_clients():
                client_id, listen_url, caps = _extract_client_info(doc)
                if not client_id or not listen_url:
                    continue
                try:
                    await _poll_client(http, client_id, listen_url, caps)
                except httpx.TimeoutException:
                    _update_poll_status(client_id, status="timeout", last_error="timeout")
                except Exception as exc:
                    _update_poll_status(client_id, status="error", last_error=str(exc))
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

