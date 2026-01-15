"""
OpenSearch 内部 API

警告: 这是内部接口，仅供特定模块使用（例如 API routes、Neo4j ingest、测试/脚本）。
内部接口可能在不通知的情况下变更，业务代码应优先使用公开接口：
  - from app.services.opensearch import store_events, run_data_analysis
"""

# 客户端操作
from .client import get_client, reset_client

# 索引管理
from .index import (
    INDEX_PATTERNS,
    get_index_name,
    hash_token,
    initialize_indices,
)
from .client import index_exists, ensure_index

# 查询操作
from .client import search, get_document

# 存储操作（用于特殊场景）
from .storage import route_to_index

__all__ = [
    # 客户端
    "get_client",
    "reset_client",
    # 索引
    "INDEX_PATTERNS",
    "get_index_name",
    "hash_token",
    "index_exists",
    "initialize_indices",
    "ensure_index",
    # 查询
    "search",
    "get_document",
    # 存储
    "route_to_index",
]

