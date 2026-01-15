"""
Neo4j 内部 API

警告: 这是内部接口，仅供特定模块使用（例如 API routes、分析模块、测试/脚本）。
内部接口可能在不通知的情况下变更，业务代码应优先使用公开接口：
  - from app.services.neo4j import ingest_ecs_events, get_edges_in_window
"""

# 基础构建/写入（供分析模块使用）
from .db import add_node, add_edge

# 查询操作
from .db import get_node, get_edges, get_alarm_edges
from .db import get_graph_by_attack_id
from .db import get_edges_in_window
from .db import get_edges_by_task_id

# GDS 算法（用于 API routes / 分析）
from .db import gds_shortest_path_in_window

# 结果写回（用于分析模块）
from .db import write_analysis_results

# 连接管理
from .db import close

# 数据模型（供分析模块使用）
from .models import (
    GraphNode,
    GraphEdge,
    NodeType,
    RelType,
    parse_uid,
)

__all__ = [
    # 构建
    "add_node",
    "add_edge",
    # 查询
    "get_node",
    "get_edges",
    "get_alarm_edges",
    "get_graph_by_attack_id",
    "get_edges_in_window",
    "get_edges_by_task_id",
    # GDS
    "gds_shortest_path_in_window",
    # 写回
    "write_analysis_results",
    # 连接
    "close",
    # 模型
    "GraphNode",
    "GraphEdge",
    "NodeType",
    "RelType",
    "parse_uid",
]
