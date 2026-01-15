"""
OpenSearch 查询模块

提供对外的查询接口，用于从 canonical findings 中提取 source 信息
以及查询 ECS events
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone

from app.core.time import to_rfc3339
from .client import get_client, search, index_exists
from .index import INDEX_PATTERNS, get_index_name


def get_canonical_findings_sources(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 1000,
    offset: int = 0,
    sort: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """
    从 canonical findings 中提取 source 信息（ECS 格式）
    
    参数：
    - start_time: 开始时间（默认：当前时间往前推24小时）
    - end_time: 结束时间（默认：当前时间）
    - limit: 返回结果数量限制（默认：1000，最大：10000）
    - offset: 分页偏移量（默认：0）
    - sort: 排序规则（默认：按 @timestamp 降序）
        示例: [{"@timestamp": {"order": "desc"}}]
    
    返回: List[Dict[str, Any]] - ECS 格式的 source 列表
        每个 source 是完整的 canonical finding 文档（ECS 格式）
    """
    client = get_client()
    
    # 默认时间范围：最近24小时
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    if start_time is None:
        start_time = end_time - timedelta(hours=24)
    
    # 限制最大返回数量
    limit = min(limit, 10000)
    
    # 获取 canonical findings 索引名
    today = end_time
    canonical_index_name = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)
    
    # 检查索引是否存在
    if not index_exists(canonical_index_name):
        return []
    
    # 默认排序：按时间戳降序
    if sort is None:
        sort = [{"@timestamp": {"order": "desc"}}]
    
    try:
        # 构建查询条件（时间范围）
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_rfc3339(start_time),
                                "lte": to_rfc3339(end_time)
                            }
                        }
                    }
                ]
            }
        }
        
        # 执行查询
        response = client.search(
            index=canonical_index_name,
            body={
                "query": query,
                "size": limit,
                "from": offset,
                "sort": sort
            }
        )
        
        # 提取结果
        hits = response.get('hits', {})
        total = hits.get('total', {})
        if isinstance(total, dict):
            total_count = total.get('value', 0)
        else:
            total_count = total
        
        # 提取 source（整个 finding 文档就是 ECS 格式的 source）
        sources = []
        for hit in hits.get('hits', []):
            finding = hit.get('_source', {})
            # 可选：添加文档元数据
            finding['_id'] = hit.get('_id')
            finding['_index'] = hit.get('_index')
            sources.append(finding)
        
        return sources
        
    except Exception as e:
        error_str = str(e)
        # 如果是索引不存在的错误，返回空结果而不是抛出异常
        if 'index_not_found' in error_str.lower() or '404' in error_str:
            print(f"[INFO] Canonical findings 索引不存在: {canonical_index_name}，返回空结果")
            return []
        print(f"[ERROR] 查询 canonical findings sources 失败: {e}")
        raise


def get_canonical_findings_sources_by_fingerprint(
    fingerprint: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 1000
) -> List[Dict[str, Any]]:
    """
    根据 fingerprint 从 canonical findings 中提取 source 信息
    
    参数：
    - fingerprint: Finding 指纹（custom.finding.fingerprint）
    - start_time: 开始时间（默认：当前时间往前推24小时）
    - end_time: 结束时间（默认：当前时间）
    - limit: 返回结果数量限制（默认：1000）
    
    返回: List[Dict[str, Any]] - ECS 格式的 source 列表
    """
    # 默认时间范围：最近24小时
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    if start_time is None:
        start_time = end_time - timedelta(hours=24)
    
    # 获取 canonical findings 索引名
    today = end_time
    canonical_index_name = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)
    
    # 检查索引是否存在
    if not index_exists(canonical_index_name):
        return []
    
    try:
        # 构建查询条件（fingerprint + 时间范围）
        query = {
            "bool": {
                "must": [
                    {
                        "term": {
                            "custom.finding.fingerprint": fingerprint
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_rfc3339(start_time),
                                "lte": to_rfc3339(end_time)
                            }
                        }
                    }
                ]
            }
        }
        
        # 查询 canonical findings
        findings = search(
            canonical_index_name,
            query,
            limit
        )
        
        # 提取 source（整个 finding 文档就是 ECS 格式的 source）
        sources = []
        for finding in findings:
            sources.append(finding)
        
        return sources
        
    except Exception as e:
        print(f"[ERROR] 根据 fingerprint 查询 canonical findings sources 失败: {e}")
        return []


def get_canonical_findings_sources_by_technique(
    technique_id: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 1000
) -> List[Dict[str, Any]]:
    """
    根据 technique ID 从 canonical findings 中提取 source 信息
    
    参数：
    - technique_id: MITRE ATT&CK Technique ID（如 "T1021"）
    - start_time: 开始时间（默认：当前时间往前推24小时）
    - end_time: 结束时间（默认：当前时间）
    - limit: 返回结果数量限制（默认：1000）
    
    返回: List[Dict[str, Any]] - ECS 格式的 source 列表
    """
    # 默认时间范围：最近24小时
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    if start_time is None:
        start_time = end_time - timedelta(hours=24)
    
    # 获取 canonical findings 索引名
    today = end_time
    canonical_index_name = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)
    
    # 检查索引是否存在
    if not index_exists(canonical_index_name):
        return []
    
    try:
        # 构建查询条件（technique_id + 时间范围）
        query = {
            "bool": {
                "must": [
                    {
                        "term": {
                            "threat.technique.id": technique_id
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_rfc3339(start_time),
                                "lte": to_rfc3339(end_time)
                            }
                        }
                    }
                ]
            }
        }
        
        # 查询 canonical findings
        findings = search(
            canonical_index_name,
            query,
            limit
        )
        
        # 提取 source（整个 finding 文档就是 ECS 格式的 source）
        sources = []
        for finding in findings:
            sources.append(finding)
        
        return sources
        
    except Exception as e:
        print(f"[ERROR] 根据 technique ID 查询 canonical findings sources 失败: {e}")
        return []


def get_events(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    query_string: Optional[str] = None,
    query_dsl: Optional[Dict[str, Any]] = None,
    limit: int = 1000,
    offset: int = 0,
    sort: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """
    查询所有 ECS events
    
    参数：
    - start_time: 开始时间（默认：当前时间往前推24小时）
    - end_time: 结束时间（默认：当前时间）
    - query_string: Query String 格式的查询条件（如 "event.category:process AND host.name:server-001"）
    - query_dsl: DSL 格式的查询条件（Dict，优先级高于 query_string）
    - limit: 返回结果数量限制（默认：1000，最大：10000）
    - offset: 分页偏移量（默认：0）
    - sort: 排序规则（默认：按 @timestamp 降序）
        示例: [{"@timestamp": {"order": "desc"}}]
    
    返回: List[Dict[str, Any]] - 事件列表
    
    使用示例:
        # 1. 查询最近24小时的所有事件
        result = get_events()
        
        # 2. 查询特定时间范围的事件
        from datetime import datetime, timedelta, timezone
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=6)
        result = get_events(start_time=start, end_time=end)
        
        # 3. 使用 Query String 查询特定条件的事件
        result = get_events(
            query_string="event.category:process AND host.name:server-001",
            limit=500
        )
        
        # 4. 使用 DSL 查询
        result = get_events(
            query_dsl={
                "bool": {
                    "must": [
                        {"term": {"event.category": "network"}},
                        {"exists": {"field": "source.ip"}}
                    ]
                }
            }
        )
        
        # 5. 分页查询
        page1 = get_events(limit=100, offset=0)
        page2 = get_events(limit=100, offset=100)
        
        # 6. 自定义排序
        result = get_events(
            sort=[{"@timestamp": {"order": "asc"}}, {"host.name": {"order": "desc"}}]
        )
    """
    client = get_client()
    
    # 默认时间范围：最近24小时
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    if start_time is None:
        start_time = end_time - timedelta(hours=24)
    
    # 限制最大返回数量
    limit = min(limit, 10000)
    
    # 获取 events 索引模式（支持多日期索引）
    events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    # 构建查询条件
    if query_dsl:
        # 如果提供了 DSL 查询，直接使用（但仍需要添加时间范围）
        query = query_dsl.copy()
        if "bool" not in query:
            query = {"bool": {"must": [query]}}
        elif "must" not in query["bool"]:
            query["bool"]["must"] = []
        
        # 添加时间范围
        query["bool"]["must"].append({
            "range": {
                "@timestamp": {
                    "gte": to_rfc3339(start_time),
                    "lte": to_rfc3339(end_time)
                }
            }
        })
    elif query_string:
        # 使用 Query String 格式
        query = {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": query_string
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_rfc3339(start_time),
                                "lte": to_rfc3339(end_time)
                            }
                        }
                    }
                ]
            }
        }
    else:
        # 默认查询所有事件（仅时间范围）
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_rfc3339(start_time),
                                "lte": to_rfc3339(end_time)
                            }
                        }
                    }
                ]
            }
        }
    
    # 默认排序：按时间戳降序
    if sort is None:
        sort = [{"@timestamp": {"order": "desc"}}]
    
    try:
        # 执行查询
        response = client.search(
            index=events_index_pattern,
            body={
                "query": query,
                "size": limit,
                "from": offset,
                "sort": sort
            }
        )
        
        # 提取结果
        hits = response.get('hits', {})
        total = hits.get('total', {})
        if isinstance(total, dict):
            total_count = total.get('value', 0)
        else:
            total_count = total
        
        events = []
        for hit in hits.get('hits', []):
            event = hit.get('_source', {})
            # 可选：添加文档元数据
            event['_id'] = hit.get('_id')
            event['_index'] = hit.get('_index')
            events.append(event)
        
        return events
        
    except Exception as e:
        error_str = str(e)
        # 如果是索引不存在的错误，返回空结果而不是抛出异常
        if 'index_not_found' in error_str.lower() or '404' in error_str:
            print(f"[INFO] Events 索引不存在: {events_index_pattern}，返回空结果")
            return []
        print(f"[ERROR] 查询 events 失败: {e}")
        raise


def get_all_data(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    query_string: Optional[str] = None,
    query_dsl: Optional[Dict[str, Any]] = None,
    limit: int = 1000,
    offset: int = 0,
    sort: Optional[List[Dict[str, Any]]] = None,
    include_events: bool = True,
    include_findings: bool = True
) -> Dict[str, Any]:
    """
    统一查询接口：同时查询 ECS events 和 canonical findings
    
    参数：
    - start_time: 开始时间（默认：当前时间往前推24小时）
    - end_time: 结束时间（默认：当前时间）
    - query_string: Query String 格式的查询条件（仅用于 events 查询）
    - query_dsl: DSL 格式的查询条件（仅用于 events 查询，优先级高于 query_string）
    - limit: 返回结果数量限制（默认：1000，最大：10000）
    - offset: 分页偏移量（默认：0）
    - sort: 排序规则（默认：按 @timestamp 降序）
    - include_events: 是否包含 events（默认：True）
    - include_findings: 是否包含 findings（默认：True）
    
    返回: Dict[str, Any] - 包含以下字段：
        - "events": List[Dict[str, Any]] - 事件列表（如果 include_events=True）
        - "findings": List[Dict[str, Any]] - findings 列表（如果 include_findings=True）
    
    使用示例:
        # 查询所有数据
        result = get_all_data()
        events = result.get("events", [])
        findings = result.get("findings", [])
        
        # 只查询 events
        result = get_all_data(include_findings=False)
        
        # 只查询 findings
        result = get_all_data(include_events=False)
        
        # 使用查询条件（仅对 events 生效）
        result = get_all_data(
            query_string="event.category:process",
            limit=500
        )
    """
    result = {}
    
    # 查询 events
    if include_events:
        try:
            events = get_events(
                start_time=start_time,
                end_time=end_time,
                query_string=query_string,
                query_dsl=query_dsl,
                limit=limit,
                offset=offset,
                sort=sort
            )
            result["events"] = events
        except Exception as e:
            print(f"[WARNING] 查询 events 失败: {e}")
            result["events"] = []
    
    # 查询 findings
    if include_findings:
        try:
            findings = get_canonical_findings_sources(
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                offset=offset,
                sort=sort
            )
            result["findings"] = findings
        except Exception as e:
            print(f"[WARNING] 查询 findings 失败: {e}")
            result["findings"] = []
    
    return result
