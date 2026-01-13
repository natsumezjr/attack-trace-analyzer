# OpenSearch 存储相关功能（数据路由、批量存储、去重）

from typing import Any
from datetime import datetime, timezone

from .client import bulk_index, get_document, refresh_index
from .index import INDEX_PATTERNS, get_index_name


def _utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _to_rfc3339(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        return s.replace("+00:00", "Z")
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, (int, float)):
        # Heuristic: milliseconds if value is large enough.
        if value > 1e12:
            ts = datetime.fromtimestamp(float(value) / 1000.0, tz=timezone.utc)
        else:
            ts = datetime.fromtimestamp(float(value), tz=timezone.utc)
        return ts.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return None


def _extract_timestamp(doc: dict[str, Any]) -> str | None:
    ts = _to_rfc3339(doc.get("@timestamp"))
    if ts:
        return ts

    event_obj = doc.get("event")
    if isinstance(event_obj, dict):
        ts = _to_rfc3339(event_obj.get("created"))
        if ts:
            return ts

    # Legacy/alternate: flattened keys.
    ts = _to_rfc3339(doc.get("event.created"))
    if ts:
        return ts

    return None


def _normalize_three_timestamps(doc: dict[str, Any], *, ingested_now: str) -> dict[str, Any] | None:
    """
    Enforce docs/51-ECS字段规范.md 三时间字段：
    - @timestamp: 主时间轴（必须可推导；否则丢弃）
    - event.created: 观察时间（缺失则回填为 @timestamp）
    - event.ingested: 中心侧入库时间（总是覆盖为 now）
    """
    ts = _extract_timestamp(doc)
    if not ts:
        return None

    doc["@timestamp"] = ts

    # Normalize legacy flattened keys into the nested event object.
    legacy_created = _to_rfc3339(doc.pop("event.created", None))
    doc.pop("event.ingested", None)

    event_obj = doc.get("event")
    if not isinstance(event_obj, dict):
        event_obj = {}
        doc["event"] = event_obj

    created = _to_rfc3339(event_obj.get("created")) or legacy_created or ts
    event_obj["created"] = created

    # Decision: center always overwrites event.ingested.
    event_obj["ingested"] = ingested_now

    return doc


def route_to_index(item: dict[str, Any]) -> str:
    """根据event.kind和event.dataset路由到对应索引"""
    event = item.get("event", {})
    kind = event.get("kind") or item.get("event.kind")
    dataset = event.get("dataset") or item.get("event.dataset", "")

    today = datetime.now()

    if kind == "event":
        # Telemetry -> ecs-events-*
        return get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
    elif kind == "alert":
        if dataset == "finding.canonical":
            # Canonical Findings -> canonical-findings-*
            return get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)
        else:
            # Raw Findings -> raw-findings-*
            return get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)

    # 默认路由到ecs-events
    return get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)


def _get_event_id(event: dict[str, Any]) -> str | None:
    """从事件中提取event.id"""
    return event.get("event", {}).get("id") or event.get("event.id")


def _is_duplicate(index_name: str, event_id: str) -> bool:
    """检查事件是否已存在（去重）"""
    if not event_id:
        return False
    existing = get_document(index_name, event_id)
    return existing is not None


def store_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """
    存储数据到OpenSearch（自动路由到对应索引，并去重）
    
    去重逻辑：在入库时检查 event.id 是否已存在，如果存在则丢弃，不存在则存储
    
    Returns:
        {
            "total": int,      # 总事件数
            "success": int,     # 成功存储数（去重后）
            "failed": int,      # 失败数
            "duplicated": int,  # 重复数（被丢弃的）
            "details": {        # 每个索引的详细统计
                "index_name": {
                    "success": int,
                    "failed": int,
                    "duplicated": int
                }
            }
        }
    """
    if len(events) == 0:
        return {"total": 0, "success": 0, "failed": 0, "duplicated": 0, "dropped": 0, "details": {}}

    # 按索引分组，并去重
    index_groups: dict[str, list[dict[str, Any]]] = {}
    total_duplicated = 0
    total_dropped = 0
    ingested_now = _utc_now_rfc3339()

    for event in events:
        if _normalize_three_timestamps(event, ingested_now=ingested_now) is None:
            total_dropped += 1
            continue

        index_name = route_to_index(event)
        event_id = _get_event_id(event)

        # 去重检查：如果event.id已存在，则跳过
        if event_id and _is_duplicate(index_name, event_id):
            total_duplicated += 1
            continue

        if index_name not in index_groups:
            index_groups[index_name] = []
        index_groups[index_name].append({
            "id": event_id,
            "document": event,
        })

    # 批量写入每个索引
    details: dict[str, dict[str, int]] = {}
    total_success = 0
    total_failed = 0

    for index_name, documents in index_groups.items():
        try:
            result = bulk_index(index_name, documents)
            details[index_name] = {
                "success": result["success"],
                "failed": result.get("failed", 0),
                "duplicated": 0,  # 去重已在上面完成
            }
            total_success += result["success"]
            total_failed += result.get("failed", 0)
            # 刷新索引，使新文档立即可搜索
            if result["success"] > 0:
                refresh_index(index_name)
        except Exception as error:
            print(f"存储到索引 {index_name} 失败: {error}")
            details[index_name] = {
                "success": 0,
                "failed": len(documents),
                "duplicated": 0,
            }
            total_failed += len(documents)

    return {
        "total": len(events),
        "success": total_success,
        "failed": total_failed,
        "duplicated": total_duplicated,
        "dropped": total_dropped,
        "details": details,
    }
