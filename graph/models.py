# graph_models.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha1
import json
from typing import Any, Dict, Optional, Literal

from pydantic import BaseModel, Field


# ---------- 1) 节点类型（枚举） ----------
class NodeType(str, Enum):
    HOST = "Host"
    USER = "User"
    SESSION = "Session"
    PROCESS = "Process"
    FILE = "File"
    DOMAIN = "Domain"
    IP = "IP"
    ENDPOINT = "Endpoint"   # ip:port 可选


# ---------- 2) 关系类型（枚举） ----------
class RelType(str, Enum):
    # 主机/网络
    COMMUNICATES_WITH = "COMMUNICATES_WITH"   # Host -> Host (netflow/zeek/suricata)
    CONNECTS_TO = "CONNECTS_TO"               # Process/Host -> Endpoint/IP
    RESOLVES = "RESOLVES"                     # Host/Process -> Domain
    RESOLVES_TO = "RESOLVES_TO"               # Domain -> IP

    # 主机内部行为
    LOGON = "LOGON"                           # User -> Session
    ON_HOST = "ON_HOST"                       # Process/User/Session -> Host
    SPAWNED = "SPAWNED"                       # Process(parent) -> Process(child)
    ACCESSED = "ACCESSED"                     # Process -> File
    WROTE = "WROTE"                           # Process -> File

    # 关联/溯源输出
    SAME_ATTACK = "SAME_ATTACK"               # Event/Entity -> Event/Entity (聚类结果)
    CAUSED_BY = "CAUSED_BY"                   # Event -> Event (因果推断)
    MAPPED_TO_ATTACK = "MAPPED_TO_ATTACK"     # Event -> AttackStage(可选你们不建节点也行)


# ---------- 3) 统一的 UID 生成 ----------
def make_uid(ntype: NodeType, key: Dict[str, Any]) -> str:
    """
    给每个实体生成稳定唯一ID，避免重复入库。
    key 必须只放“能唯一标识这个实体”的字段。
    """
    raw = json.dumps(key, sort_keys=True, ensure_ascii=False)
    h = sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"{ntype.value}:{h}"


# ---------- 4) 节点 / 边的数据结构 ----------
class GraphNode(BaseModel):
    uid: str
    ntype: NodeType
    key: Dict[str, Any] = Field(default_factory=dict)      # 唯一键
    props: Dict[str, Any] = Field(default_factory=dict)    # 其它属性（可包含ECS字段子集）


class GraphEdge(BaseModel):
    src_uid: str
    dst_uid: str
    rtype: RelType
    # 关系属性：时间、证据源、ATT&CK标签、置信度等
    props: Dict[str, Any] = Field(default_factory=dict)


# ---------- 5) 你们确认的“实体键”规范 ----------
def host_node(host_name: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"host.name": host_name}
    return GraphNode(uid=make_uid(NodeType.HOST, key), ntype=NodeType.HOST, key=key, props=props or {})

def user_node(user_name: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"user.name": user_name}
    return GraphNode(uid=make_uid(NodeType.USER, key), ntype=NodeType.USER, key=key, props=props or {})

def session_node(host_name: str, session_id: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    # 注意：session_id 通常不是全局唯一，必须加 host 维度
    key = {"host.name": host_name, "session.id": session_id}
    return GraphNode(uid=make_uid(NodeType.SESSION, key), ntype=NodeType.SESSION, key=key, props=props or {})

def process_node(process_entity_id: Optional[str],
                 host_name: str,
                 pid: Optional[int],
                 start_ts: Optional[str],
                 props: Optional[Dict[str, Any]] = None) -> GraphNode:
    # 优先 process.entity_id；否则退化为 host+pid+start_ts
    if process_entity_id:
        key = {"process.entity_id": process_entity_id}
    else:
        key = {"host.name": host_name, "process.pid": pid, "process.start": start_ts}
    return GraphNode(uid=make_uid(NodeType.PROCESS, key), ntype=NodeType.PROCESS, key=key, props=props or {})

def file_node(path: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"file.path": path}
    return GraphNode(uid=make_uid(NodeType.FILE, key), ntype=NodeType.FILE, key=key, props=props or {})

def domain_node(dns_query: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"dns.question.name": dns_query}
    return GraphNode(uid=make_uid(NodeType.DOMAIN, key), ntype=NodeType.DOMAIN, key=key, props=props or {})

def ip_node(ip: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"ip": ip}
    return GraphNode(uid=make_uid(NodeType.IP, key), ntype=NodeType.IP, key=key, props=props or {})

def endpoint_node(ip: str, port: int, transport: Optional[str] = None,
                  props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"ip": ip, "port": port, "transport": transport or ""}
    return GraphNode(uid=make_uid(NodeType.ENDPOINT, key), ntype=NodeType.ENDPOINT, key=key, props=props or {})
