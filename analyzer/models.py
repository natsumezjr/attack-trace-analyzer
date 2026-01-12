# analyzer/models.py
# Dependencies:
# - stdlib: dataclasses, datetime, typing, uuid

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
import uuid


@dataclass
class Event:
    """统一事件模型（ECS 子集思想），尽量只保留关联所需字段。"""
    event_id: str
    ts: datetime
    source: str                # wazuh / falco / suricata / security-analytics ...
    etype: str                 # process_create / dns / net_conn / file / alert ...
    host: str                  # host.name（主机名或唯一ID）
    session_id: Optional[str] = None
    user: Optional[str] = None

    # 统一字段（按需增减）
    process_entity_id: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_ppid: Optional[int] = None
    process_cmd: Optional[str] = None

    dns_query: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    network_proto: Optional[str] = None
    direction: Optional[str] = None  # outbound / inbound / unknown

    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    # 原始事件（便于回溯、截图、证据链接）
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    """实体关系边：把实体连起来的证据"""
    src_type: str        # process/domain/ip/file/host/user/session
    src_id: str
    relation: str        # spawned/queries/connects_to/reads/writes/logged_in_to/...
    dst_type: str
    dst_id: str
    evidence_event_ids: List[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """一次攻击实例（attack instance）"""
    chain_id: str
    host: str
    start_ts: datetime
    end_ts: datetime
    edges: List[Edge] = field(default_factory=list)

    # ATT&CK 标注（可以来自规则或后处理）
    tactics: Set[str] = field(default_factory=set)
    techniques: Set[str] = field(default_factory=set)

    # 你们自己的阶段输出（Kill Chain）
    stages: List[Dict[str, Any]] = field(default_factory=list)

    # 可选：APT 相似度结果
    apt_topn: List[Dict[str, Any]] = field(default_factory=list)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"
