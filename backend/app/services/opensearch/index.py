# OpenSearch 索引管理相关功能

import hashlib
from datetime import datetime, timezone
from typing import Optional

from .client import ensure_index
from .mappings import (
    ecs_events_mapping,
    raw_findings_mapping,
    canonical_findings_mapping,
    analysis_tasks_mapping,
    client_registry_mapping,
)

# ========== 索引常量 ==========
INDEX_PATTERNS = {
    "ECS_EVENTS": "ecs-events",
    "RAW_FINDINGS": "raw-findings",
    "CANONICAL_FINDINGS": "canonical-findings",
    "ANALYSIS_TASKS": "analysis-tasks",
    "CLIENT_REGISTRY": "client-registry",
}


def get_index_name(pattern: str, date: Optional[datetime] = None) -> str:
    """
    生成带日期的索引名（用于时间序列索引）
    
    重要：使用连字符而非点号，避免Security Analytics doc-level monitor的pattern检测
    - 旧格式（有问题）：ecs-events-2026.01.13（包含点号，会被当作pattern）
    - 新格式（正确）：ecs-events-2026-01-13（连字符，doc-level monitor接受）
    """
    if date is None:
        date = datetime.now(timezone.utc)
    # 使用连字符而非点号，避免doc-level monitor的pattern检测问题
    date_str = date.strftime("%Y-%m-%d")
    return f"{pattern}-{date_str}"


def hash_token(token: str) -> str:
    """生成token哈希"""
    return hashlib.sha256(token.encode()).hexdigest()


def initialize_indices() -> None:
    """初始化所有需要的索引"""
    today = datetime.now(timezone.utc)

    # 创建今日索引
    ensure_index(
        get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today),
        ecs_events_mapping,
    )

    ensure_index(
        get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today),
        raw_findings_mapping,
    )

    ensure_index(
        get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today),
        canonical_findings_mapping,
    )

    ensure_index(
        get_index_name(INDEX_PATTERNS["ANALYSIS_TASKS"], today),
        analysis_tasks_mapping,
    )

    # Client registry is a fixed index (not time-series).
    ensure_index(
        INDEX_PATTERNS["CLIENT_REGISTRY"],
        client_registry_mapping,
    )

    print("所有索引初始化完成")
