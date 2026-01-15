"""
OpenSearch 查询模块

提供对外的查询接口，用于从 canonical findings 中提取 source 信息
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone

from app.core.time import to_rfc3339
from .client import get_client, search, index_exists
from .index import INDEX_PATTERNS, get_index_name


def get_canonical_findings_sources(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 1000
) -> List[Dict[str, Any]]:
    """
    从 canonical findings 中提取 source 信息（ECS 格式）
    
    参数：
    - start_time: 开始时间（默认：当前时间往前推24小时）
    - end_time: 结束时间（默认：当前时间）
    - limit: 返回结果数量限制（默认：1000）
    
    返回: List[Dict[str, Any]] - ECS 格式的 source 列表
        每个 source 是完整的 canonical finding 文档（ECS 格式）
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
        
        # 查询 canonical findings
        findings = search(
            canonical_index_name,
            query,
            limit
        )
        
        # 提取 source（整个 finding 文档就是 ECS 格式的 source）
        sources = []
        for finding in findings:
            # finding 本身就是完整的 ECS 格式文档，直接返回
            # 如果需要，可以在这里进行字段过滤或转换
            sources.append(finding)
        
        return sources
        
    except Exception as e:
        print(f"[ERROR] 查询 canonical findings sources 失败: {e}")
        return []


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
