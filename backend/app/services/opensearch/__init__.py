"""
OpenSearch 统一对外接口

模块职责:
  - 存储 ECS 事件到 OpenSearch（自动路由、去重、时间字段规范化）
  - 运行 Security Analytics 检测并融合去重
  - 查询 canonical findings 的 source 信息

公开接口 (推荐使用):
  - store_events(): 存储事件到 OpenSearch
  - run_data_analysis(): 检测 + 融合去重
  - get_canonical_findings_sources(): 查询 canonical findings 的 source（ECS 格式）

内部接口 (仅用于特定场景):
  - 使用: from app.services.opensearch.internal import ...
  - 警告: internal 接口不保证稳定性
"""

# 公开接口（高层业务 API）
from .storage import store_events
from .analysis import run_data_analysis
from .query import get_canonical_findings_sources

__all__ = [
    "store_events",
    "run_data_analysis",
    "get_canonical_findings_sources",
]

