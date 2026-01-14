# Neo4j ECS 入图模块
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

# Optional: ECS ingest integration (legacy compatibility)
try:
    from .ecs_ingest import ecs_event_to_graph  # type: ignore
except Exception:
    ecs_event_to_graph = None  # type: ignore

from . import db
from . import models


# =============================================================================
# ECS 入图函数
# =============================================================================

def ingest_ecs_event(event: Mapping[str, Any]) -> tuple[int, int]:
    """入图：单条 ECS 文档

    将单个 ECS 事件转换为节点和边，并写入 Neo4j。

    Args:
        event: ECS 格式的事件文档

    Returns:
        tuple[int, int]: (节点数, 边数)

    Raises:
        NotImplementedError: 当 ecs_event_to_graph 不可用时
    """
    if ecs_event_to_graph is None:
        raise NotImplementedError("ecs_event_to_graph is not available")

    nodes, edges = ecs_event_to_graph(event)
    for node in nodes:
        db.add_node(node)
    for edge in edges:
        db.add_edge(edge)
    return len(nodes), len(edges)


def ingest_ecs_events(events: Iterable[Mapping[str, Any]]) -> tuple[int, int]:
    """入图：批量 ECS 文档

    将多个 ECS 事件转换为节点和边，并批量写入 Neo4j。

    Args:
        events: ECS 格式的事件文档可迭代对象

    Returns:
        tuple[int, int]: (总节点数, 总边数)

    Raises:
        NotImplementedError: 当 ecs_event_to_graph 不可用时
    """
    if ecs_event_to_graph is None:
        raise NotImplementedError("ecs_event_to_graph is not available")

    total_nodes = 0
    total_edges = 0
    for event in events:
        nodes, edges = ecs_event_to_graph(event)
        for node in nodes:
            db.add_node(node)
        for edge in edges:
            db.add_edge(edge)
        total_nodes += len(nodes)
        total_edges += len(edges)
    return total_nodes, total_edges


def ingest_from_opensearch(
    query: Mapping[str, Any] | None = None,
    *,
    size: int = 100,
    include_events: bool = True,
    include_raw_findings: bool = False,
    include_canonical_findings: bool = True,
    date: datetime | None = None,
) -> tuple[int, int, int]:
    """从 OpenSearch 拉取并入图

    从 OpenSearch 索引中拉取 ECS 事件，并写入 Neo4j 图数据库。

    Args:
        query: OpenSearch 查询条件，None 表示匹配所有
        size: 每个索引拉取的最大文档数
        include_events: 是否包含 Telemetry 事件
        include_raw_findings: 是否包含 Raw Findings
        include_canonical_findings: 是否包含 Canonical Findings
        date: 索引日期，None 表示使用当前日期

    Returns:
        tuple[int, int, int]: (总事件数, 总节点数, 总边数)
    """
    # 使用 OpenSearch API 拉取 ECS 事件并写入 Neo4j
    from ..opensearch import INDEX_PATTERNS, get_index_name, index_exists, search

    query_body = dict(query) if query is not None else {"match_all": {}}
    index_names: list[str] = []
    if include_events:
        index_names.append(get_index_name(INDEX_PATTERNS["ECS_EVENTS"], date))
    if include_raw_findings:
        index_names.append(get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], date))
    if include_canonical_findings:
        index_names.append(get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], date))

    total_events = 0
    total_nodes = 0
    total_edges = 0

    for index_name in index_names:
        if not index_exists(index_name):
            continue
        events = search(index_name, query_body, size=size)
        if not events:
            continue
        total_events += len(events)
        node_count, edge_count = ingest_ecs_events(events)
        total_nodes += node_count
        total_edges += edge_count

    return total_events, total_nodes, total_edges
