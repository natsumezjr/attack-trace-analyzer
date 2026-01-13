# OpenSearch Python 模块

## 📁 文件结构

```
backend/opensearch/
├── __init__.py      # 统一对外接口（唯一导入入口）
├── client.py        # 客户端配置和基础操作
├── storage.py       # 存储功能（数据路由、批量存储、去重）
├── analysis.py      # 数据分析功能（检测和去重）
├── mappings.py      # 索引映射定义
├── index.py         # 索引管理功能
└── README.md        # 本文件
```

## 🎯 快速开始

### 标准导入

```python
from opensearch import (
    # 存储功能
    store_events,
    
    # 数据分析
    run_data_analysis,
    
    # 查询功能
    search_documents,
    get_document,
    
    # 索引管理
    INDEX_PATTERNS,
    get_index_name,
    initialize_indices,
)
```

## 📚 核心功能

### 1. 存储事件（自动路由 + 去重）

```python
from opensearch import store_events

result = store_events([
    {"event": {"kind": "event", "id": "evt-1", ...}, ...},
    {"event": {"kind": "alert", "dataset": "finding.raw", ...}, ...},
])

# 自动路由到对应索引，并去重：
# - event.kind='event' → ecs-events-*
# - event.kind='alert' + dataset='finding.raw' → raw-findings-*
# - event.kind='alert' + dataset='finding.canonical' → canonical-findings-*
# 
# 去重逻辑：根据 event.id 检查是否已存在，重复则丢弃
# 返回: {"total": int, "success": int, "failed": int, "duplicated": int, "details": {...}}
```

### 2. 数据分析

```python
from opensearch import run_data_analysis

# 执行数据分析（检测 + 去重）
result = run_data_analysis()
# {
#   "detection": {"success": bool, "message": str},
#   "deduplication": {"total": int, "merged": int, "canonical": int, "errors": int}
# }
```

### 3. 查询数据

```python
from opensearch import search_documents, get_index_name, INDEX_PATTERNS

index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"])
results = search_documents(index_name, {"match_all": {}}, 100)
```

### 4. 初始化索引

```python
from opensearch import initialize_indices

initialize_indices()  # 自动创建所有需要的索引
```

## 📋 索引常量

```python
INDEX_PATTERNS["ECS_EVENTS"]          # 'ecs-events'
INDEX_PATTERNS["RAW_FINDINGS"]         # 'raw-findings'
INDEX_PATTERNS["CANONICAL_FINDINGS"]   # 'canonical-findings'
INDEX_PATTERNS["ATTACK_CHAINS"]        # 'attack-chains'
INDEX_PATTERNS["CLIENT_REGISTRY"]       # 'client-registry'
```

## 🔑 去重功能

在 `store_events()` 函数中实现了入库时去重：

- **去重依据**：`event.id` 字段
- **去重逻辑**：在存储前检查该 `event.id` 是否已在索引中存在
- **行为**：如果存在则丢弃，不存在则存储
- **返回统计**：`duplicated` 字段表示被丢弃的重复记录数

## ⚠️ 重要提示

1. **统一导入**：只从 `opensearch` 导入，不要直接导入内部文件
2. **自动路由**：`store_events` 会根据 `event.kind` 和 `event.dataset` 自动路由
3. **去重**：入库时自动去重，基于 `event.id`
4. **数据分析**：使用 `run_data_analysis()` 执行完整的数据分析流程

## 📖 详细文档

- **[API 参考文档](./API_REFERENCE.md)** - 每个接口的详细说明和使用示例

## 🔧 环境变量

```bash
OPENSEARCH_NODE=https://localhost:9200
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=OpenSearch@2024!Dev
```

## 📦 依赖

- `opensearch-py>=2.0.0`

安装方式：
```bash
uv add opensearch-py
# 或
pip install opensearch-py
```
