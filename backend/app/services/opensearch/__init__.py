"""
OpenSearch 统一对外接口

模块职责:
  - 存储 ECS 事件到 OpenSearch（自动路由、去重、时间字段规范化）
  - 运行 Security Analytics 检测并融合去重
  - 查询 canonical findings 的 source 信息
  - 查询 ECS events

公开接口 (推荐使用):
  - store_events(): 存储事件到 OpenSearch
  - run_data_analysis(): 检测 + 融合去重
  - get_canonical_findings_sources(): 查询 canonical findings 的 source（ECS 格式）
    参数: start_time, end_time, limit, offset, sort
    返回: List[Dict[str, Any]] - source 列表
  - get_events(): 查询所有 ECS events
    参数: start_time, end_time, query_string, query_dsl, limit, offset, sort
    返回: List[Dict[str, Any]] - 事件列表
  - get_all_data(): 统一查询接口，同时查询 events 和 findings
    参数: start_time, end_time, query_string, query_dsl, limit, offset, sort, include_events, include_findings
    返回: Dict[str, Any] - 包含 "events" 和 "findings" 字段

内部接口 (仅用于特定场景):
  - 使用: from app.services.opensearch.internal import ...
  - 警告: internal 接口不保证稳定性
"""

# 公开接口（高层业务 API）
from .storage import store_events
from .analysis import run_data_analysis
from .query import get_canonical_findings_sources, get_events, get_all_data

__all__ = [
    "store_events",
    "run_data_analysis",
    "get_canonical_findings_sources",
    "get_events",
    "get_all_data",
]

