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


