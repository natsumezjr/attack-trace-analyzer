# OpenSearch 统一对外接口
# 这是唯一应该被外部代码导入的文件

from .client import (
    get_client,
    index_exists,
    ensure_index,
    search,
    get_document,
    update_document,
    index_document,
    bulk_index,
)
from .index import (
    INDEX_PATTERNS,
    get_index_name,
    hash_token,
    initialize_indices,
)
from .storage import store_events, route_to_index
from .analysis import (
    run_data_analysis,
    deduplicate_findings,
    run_security_analytics,
)
from .mappings import (
    ecs_events_mapping,
    raw_findings_mapping,
    canonical_findings_mapping,
    attack_chains_mapping,
    client_registry_mapping,
)

# 向后兼容：导出旧函数名
get_open_search_client = get_client
search_documents = search

__all__ = [
    # 客户端操作
    "get_client",
    "get_open_search_client",
    "index_exists",
    "ensure_index",
    "search",
    "search_documents",
    "get_document",
    "update_document",
    "index_document",
    "bulk_index",
    # 索引管理
    "INDEX_PATTERNS",
    "get_index_name",
    "hash_token",
    "initialize_indices",
    # 存储功能
    "store_events",
    "route_to_index",
    # 数据分析
    "run_data_analysis",
    "deduplicate_findings",
    "run_security_analytics",
    # 索引映射
    "ecs_events_mapping",
    "raw_findings_mapping",
    "canonical_findings_mapping",
    "attack_chains_mapping",
    "client_registry_mapping",
]
