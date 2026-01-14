from __future__ import annotations

from threading import RLock


# 内存中的在线靶机表（后续需要可持久化再替换）
# 结构：{ip1, ip2, ...}
_REGISTRY: set[str] = set()
_LOCK = RLock()


def register_target(ip: str) -> None:
    # 注册在线靶机（仅存 IP）
    with _LOCK:
        _REGISTRY.add(ip)


def list_targets() -> list[str]:
    # 读取当前注册的 IP 列表
    with _LOCK:
        return list(_REGISTRY)


def remove_target(ip: str) -> None:
    # 移除超时的在线靶机
    with _LOCK:
        _REGISTRY.discard(ip)
