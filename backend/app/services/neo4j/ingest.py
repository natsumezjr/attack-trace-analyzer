# Neo4j ECS 入图模块
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional, Tuple

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
    """入图：批量 ECS 文档（使用批量 API）

    性能优化：使用 add_nodes_and_edges() 批量写入，减少网络往返。
    优化前：1000 事件 ~16000 次网络往返，耗时 ~50 秒
    优化后：1000 事件 ~160 次网络往返，耗时 <5 秒

    Args:
        events: ECS 格式的事件文档可迭代对象

    Returns:
        tuple[int, int]: (总节点数, 总边数)

    Raises:
        NotImplementedError: 当 ecs_event_to_graph 不可用时

    Notes:
        - 所有节点和边先收集到内存，然后在单个事务中批量写入
        - 内存占用：1000 事件约增加 10-20 MB（临时）
        - 幂等性：与单条写入完全一致
    """
    if ecs_event_to_graph is None:
        raise NotImplementedError("ecs_event_to_graph is not available")

    # 第一步：收集所有节点和边
    all_nodes: list[models.GraphNode] = []
    all_edges: list[models.GraphEdge] = []

    for event in events:
        nodes, edges = ecs_event_to_graph(event)
        all_nodes.extend(nodes)
        all_edges.extend(edges)

    # 第二步：批量写入（单个事务）
    return db.add_nodes_and_edges(all_nodes, all_edges)


def _extract_range_from_query(query: Mapping[str, Any] | None) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Best-effort extract @timestamp range from a simple OpenSearch DSL query."""
    if not isinstance(query, Mapping):
        return None, None

    def _scan(obj: Any) -> Optional[dict[str, Any]]:
        if isinstance(obj, Mapping):
            if "range" in obj and isinstance(obj["range"], Mapping):
                return obj["range"]
            for value in obj.values():
                found = _scan(value)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = _scan(item)
                if found:
                    return found
        return None

    range_query = _scan(query)
    if not range_query:
        return None, None

    ts_range = range_query.get("@timestamp")
    if not isinstance(ts_range, Mapping):
        return None, None

    def _parse_dt(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None

    start = _parse_dt(ts_range.get("gte") or ts_range.get("gt"))
    end = _parse_dt(ts_range.get("lte") or ts_range.get("lt"))
    return start, end


def _extract_term_from_query(query: Mapping[str, Any] | None, field: str) -> Optional[str]:
    """Best-effort extract term value for a field from a simple OpenSearch DSL query."""
    if not isinstance(query, Mapping):
        return None

    def _scan(obj: Any) -> Optional[str]:
        if isinstance(obj, Mapping):
            term = obj.get("term")
            if isinstance(term, Mapping) and field in term:
                value = term.get(field)
                return value if isinstance(value, str) and value else None
            for value in obj.values():
                found = _scan(value)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = _scan(item)
                if found:
                    return found
        return None

    return _scan(query)


def _date_to_window(date: datetime) -> Tuple[datetime, datetime]:
    """Convert a date/datetime to a UTC day window."""
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    start = datetime(date.year, date.month, date.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return start, end


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
    # 使用 OpenSearch 对外查询接口拉取 Canonical Findings source 并写入 Neo4j
    from ..opensearch.query import (
        get_canonical_findings_sources,
        get_canonical_findings_sources_by_fingerprint,
        get_canonical_findings_sources_by_technique,
    )

    if include_events or include_raw_findings:
        print("[INFO] Neo4j ingest skips events/raw findings; using canonical findings sources only.")

    start_time, end_time = _extract_range_from_query(query)
    if date is not None and start_time is None and end_time is None:
        start_time, end_time = _date_to_window(date)

    fingerprint = _extract_term_from_query(query, "custom.finding.fingerprint")
    technique_id = _extract_term_from_query(query, "threat.technique.id")

    total_events = 0
    total_nodes = 0
    total_edges = 0

    if include_canonical_findings:
        if fingerprint:
            events = get_canonical_findings_sources_by_fingerprint(
                fingerprint=fingerprint,
                start_time=start_time,
                end_time=end_time,
                limit=size,
            )
        elif technique_id:
            events = get_canonical_findings_sources_by_technique(
                technique_id=technique_id,
                start_time=start_time,
                end_time=end_time,
                limit=size,
            )
        else:
            events = get_canonical_findings_sources(
                start_time=start_time,
                end_time=end_time,
                limit=size,
            )
        if events:
            total_events += len(events)
            node_count, edge_count = ingest_ecs_events(events)
            total_nodes += node_count
            total_edges += edge_count

    return total_events, total_nodes, total_edges


def ingest_from_opensearch_ingested_window(
    *,
    start_time: datetime,
    end_time: datetime,
    size: int = 5000,
    include_events: bool = True,
    include_canonical_findings: bool = True,
) -> tuple[int, int, int]:
    """从 OpenSearch 拉取并入图（按 event.ingested 时间窗）

    轮询 tick 内入库/分析写回的文档，其 event.ingested 会被中心机覆盖为“入库时间”。
    因此，tick 级入图应按 event.ingested 做窗口过滤，避免 canonical 的 @timestamp
    较早导致“本 tick 生成但没被入图”的遗漏。

    Args:
        start_time: event.ingested 起始时间（UTC）
        end_time: event.ingested 结束时间（UTC）
        size: 每个索引拉取的最大文档数（单次 search）
        include_events: 是否包含 Telemetry（ecs-events-*）
        include_canonical_findings: 是否包含 Canonical Findings（canonical-findings-*）

    Returns:
        tuple[int, int, int]: (总事件数, 总节点数, 总边数)
    """
    from app.core.time import format_rfc3339
    from ..opensearch.client import get_client as get_opensearch_client
    from ..opensearch.index import INDEX_PATTERNS as OPENSEARCH_INDEX_PATTERNS

    start_rfc3339 = format_rfc3339(start_time)
    end_rfc3339 = format_rfc3339(end_time)

    def _search_sources(index_pattern: str, *, kind: str, dataset: str | None = None) -> list[dict[str, Any]]:
        query: dict[str, Any] = {
            "bool": {
                "must": [
                    {"term": {"event.kind": kind}},
                    {"range": {"event.ingested": {"gte": start_rfc3339, "lte": end_rfc3339}}},
                ]
            }
        }
        if dataset is not None:
            query["bool"]["must"].append({"term": {"event.dataset": dataset}})

        client = get_opensearch_client()
        resp = client.search(
            index=index_pattern,
            body={
                "query": query,
                "size": min(int(size), 10000),
                "sort": [{"event.ingested": {"order": "asc"}}],
            },
        )
        hits = (resp or {}).get("hits", {}).get("hits", [])
        docs: list[dict[str, Any]] = []
        for hit in hits:
            src = hit.get("_source")
            if isinstance(src, dict):
                docs.append(src)
        return docs

    total_events = 0
    total_nodes = 0
    total_edges = 0

    if include_events:
        events = _search_sources(
            f"{OPENSEARCH_INDEX_PATTERNS['ECS_EVENTS']}-*",
            kind="event",
        )
        if events:
            total_events += len(events)
            node_count, edge_count = ingest_ecs_events(events)
            total_nodes += node_count
            total_edges += edge_count

    if include_canonical_findings:
        canonical = _search_sources(
            f"{OPENSEARCH_INDEX_PATTERNS['CANONICAL_FINDINGS']}-*",
            kind="alert",
            dataset="finding.canonical",
        )
        if canonical:
            total_events += len(canonical)
            node_count, edge_count = ingest_ecs_events(canonical)
            total_nodes += node_count
            total_edges += edge_count

    return total_events, total_nodes, total_edges
