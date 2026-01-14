from __future__ import annotations

import asyncio
import logging
import os

import httpx

from app.services.online_targets.registry import list_targets, remove_target
from app.services.opensearch import store_events


_LOGGER = logging.getLogger(__name__)

_stop_event: asyncio.Event | None = None
_poll_task: asyncio.Task[None] | None = None


def _poll_interval_seconds() -> int:
    # 轮询间隔（秒）
    raw = os.getenv("TARGET_POLL_INTERVAL_SECONDS", "5").strip()
    try:
        value = int(raw, 10)
    except ValueError:
        return 5
    return max(1, min(value, 3600))


def _poll_url(route: str, ip: str) -> str:
    # 轮询请求的目标地址：路由固定
    scheme = os.getenv("TARGET_POLL_SCHEME", "http").strip() or "http"
    return f"{scheme}://{ip}/{route}"


def _poll_timeout() -> httpx.Timeout:
    # 请求超时配置
    raw = os.getenv("TARGET_POLL_TIMEOUT_SECONDS", "5").strip()
    try:
        value = float(raw)
    except ValueError:
        value = 5.0
    return httpx.Timeout(value, connect=min(2.0, value))


async def _poll_loop(stop_event: asyncio.Event) -> None:
    # 后台轮询循环
    routes = ["falco", "suricata", "filebeat"]
    async with httpx.AsyncClient(timeout=_poll_timeout()) as client:
        while not stop_event.is_set():
            targets = list_targets()
            for ip in targets:
                timed_out = await _poll_target_routes(client, ip, routes)
                if timed_out:
                    remove_target(ip)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=_poll_interval_seconds())
            except asyncio.TimeoutError:
                continue


async def _poll_target_routes(
    client: httpx.AsyncClient,
    ip: str,
    routes: list[str],
) -> bool:
    for route in routes:
        url = _poll_url(route, ip)
        try:
            raw_data = await _fetch_raw_data(client, url, retries=3)
        except httpx.TimeoutException:
            _LOGGER.debug("poll target timeout: %s", ip)
            return True
        except Exception as exc:
            _LOGGER.debug("poll target failed: %s (%s)", ip, exc)
            continue

        # 直接使用靶机返回的原始数据，不做封装
        if isinstance(raw_data, dict) and isinstance(raw_data.get("data"), list):
            store_events(raw_data["data"])
        else:
            _LOGGER.debug("target response from %s: %s", url, raw_data)
    return False


async def _fetch_raw_data(
    client: httpx.AsyncClient,
    url: str,
    retries: int,
) -> object:
    response = await _post_with_retries(client, url, retries=retries)
    response.raise_for_status()
    try:
        return response.json()
    except ValueError:
        return response.text


async def _post_with_retries(
    client: httpx.AsyncClient,
    url: str,
    retries: int,
) -> httpx.Response:
    for attempt in range(retries):
        try:
            return await client.post(url, content=b"")
        except httpx.TimeoutException:
            if attempt == retries - 1:
                raise
            continue


async def start_polling() -> None:
    # 启动后台轮询任务
    global _stop_event, _poll_task

    if _poll_task and not _poll_task.done():
        return

    _stop_event = asyncio.Event()
    _poll_task = asyncio.create_task(_poll_loop(_stop_event))


async def stop_polling() -> None:
    # 停止后台轮询任务
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
