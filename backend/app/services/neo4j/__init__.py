"""
Neo4j 统一对外接口

模块职责:
  - ECS 事件入图（将 OpenSearch / ECS 事件转换为图结构并写入 Neo4j）
  - 图查询（按时间窗口查询边等）

公开接口 (推荐使用):
  - ingest_ecs_events(): 批量入图
  - get_edges_in_window(): 按时间窗口查询边

内部接口 (仅用于特定场景):
  - 使用: from app.services.neo4j.internal import ...
  - 警告: internal 接口不保证稳定性
"""

from .ingest import ingest_ecs_events
from .db import get_edges_in_window

__all__ = [
    "ingest_ecs_events",
    "get_edges_in_window",
]

