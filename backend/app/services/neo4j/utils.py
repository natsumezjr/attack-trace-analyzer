# Neo4j 工具函数集合
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from .models import NodeType, NODE_UNIQUE_KEY, build_uid


# =============================================================================
# 时间解析工具
# =============================================================================

def _parse_ts_to_float(ts: str | None) -> float:
    """
    将 UTC 时间字符串 (ISO 8601) 或 数字字符串 转换为 Unix 时间戳 (float)
    例如: "2023-10-27T10:00:00Z" -> 1698400800.0
    """
    if not ts:
        return 0.0
    # 1. 尝试直接转换为 float (兼容数据库里存的已经是秒数的情况)
    try:
        return float(ts)
    except ValueError:
        pass

    # 2. 解析 ISO 8601 格式字符串
    try:
        # 处理 'Z' 后缀：Python 3.11 以前的 fromisoformat 不支持 'Z' 结尾，
        # 需要将其替换为 '+00:00' 来表示 UTC 时区。
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'

        # 解析字符串为 datetime 对象
        dt = datetime.fromisoformat(ts)

        # 转换为 Unix 时间戳 (float 秒数)
        return dt.timestamp()

    except (ValueError, TypeError):
        # 如果格式依然无法解析，返回 0.0 作为兜底，防止程序崩溃
        return 0.0


# =============================================================================
# Cypher 查询工具
# =============================================================================

def _param_key(name: str) -> str:
    """将属性名转换为安全的 Cypher 参数键名"""
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)
    return f"key_{safe}"


def _cypher_prop(name: str) -> str:
    """将属性名转义为安全的 Cypher 属性标识符"""
    escaped = name.replace("`", "``")
    return f"`{escaped}`"


def _name_suffix(name: str) -> str:
    """将名称转换为安全的后缀字符串（用于变量名等）"""
    return "".join(ch if ch.isalnum() else "_" for ch in name)


# =============================================================================
# 数据库会话执行工具
# =============================================================================

def _execute_write(session, func, *args, **kwargs):
    """
    执行写事务（兼容 Neo4j 驱动不同版本）
    """
    if hasattr(session, "execute_write"):
        return session.execute_write(func, *args, **kwargs)
    return session.write_transaction(func, *args, **kwargs)


def _execute_read(session, func, *args, **kwargs):
    """
    执行读事务（兼容 Neo4j 驱动不同版本）
    """
    if hasattr(session, "execute_read"):
        return session.execute_read(func, *args, **kwargs)
    return session.read_transaction(func, *args, **kwargs)


# =============================================================================
# 节点记录处理工具
# =============================================================================

def _node_uid_from_record(labels: Iterable[str], props: Dict[str, Any]) -> Optional[str]:
    """
    从 Neo4j 记录的 labels 和 props 构建节点 UID
    用于查询结果转换为 GraphNode
    """
    ntype = _label_to_ntype(labels)
    if ntype is None:
        return None
    if ntype == NodeType.USER:
        user_id = props.get("user.id")
        if user_id:
            return build_uid(ntype, {"user.id": user_id})
        host_id = props.get("host.id")
        user_name = props.get("user.name")
        if host_id and user_name:
            return build_uid(ntype, {"host.id": host_id, "user.name": user_name})
    if ntype == NodeType.FILE:
        host_id = props.get("host.id")
        file_path = props.get("file.path")
        if host_id and file_path:
            return build_uid(ntype, {"host.id": host_id, "file.path": file_path})
    key_field = NODE_UNIQUE_KEY.get(ntype)
    if key_field and key_field in props:
        return build_uid(ntype, {key_field: props[key_field]})
    fallback = _fallback_key(ntype, props)
    if fallback:
        return build_uid(ntype, fallback)
    return None


def _label_to_ntype(labels: Iterable[str]) -> Optional[NodeType]:
    """
    将 Neo4j 节点标签列表转换为 NodeType 枚举
    返回第一个匹配的标签，如果没有匹配则返回 None
    """
    for label in labels:
        try:
            return NodeType(label)
        except ValueError:
            continue
    return None


def _fallback_key(ntype: NodeType, props: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    为节点类型提供备用键字段（用于构建 UID）
    当主要字段不存在时，尝试使用备用字段
    """
    fallback_fields = {
        NodeType.HOST: ["host.id", "host.name"],
        NodeType.USER: ["user.id", "host.id", "user.name"],
        NodeType.PROCESS: ["process.entity_id"],
        NodeType.FILE: ["host.id", "file.path"],
        NodeType.DOMAIN: ["domain.name"],
        NodeType.IP: ["ip"],
    }
    if ntype == NodeType.USER:
        user_id = props.get("user.id")
        if user_id:
            return {"user.id": user_id}
        host_id = props.get("host.id")
        user_name = props.get("user.name")
        if host_id and user_name:
            return {"host.id": host_id, "user.name": user_name}
        return None
    if ntype == NodeType.FILE:
        host_id = props.get("host.id")
        file_path = props.get("file.path")
        if host_id and file_path:
            return {"host.id": host_id, "file.path": file_path}
        return None

    for field in fallback_fields.get(ntype, []):
        if field in props:
            return {field: props[field]}
    return None
