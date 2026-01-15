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
