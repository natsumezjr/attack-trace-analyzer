# OpenSearch Python 模块

> **📋 完整进度总结**：[进度总结.md](./docs/进度总结.md) ⭐ **推荐阅读**

## 📁 文件结构

```
backend/app/services/opensearch/
├── __init__.py              # 统一对外接口（唯一导入入口）
├── client.py                # 客户端配置和基础操作
├── storage.py               # 存储功能（数据路由、批量存储、去重）
├── analysis.py              # 数据分析功能（检测和去重）
├── mappings.py              # 索引映射定义
├── index.py                 # 索引管理功能
├── trigger_lock.py          # Detector触发锁机制
│
├── scripts/                 # 脚本工具（规则导入、Detector配置等）
├── docs/                    # 文档目录（API参考、部署指南等）
├── test/                    # 单元测试和集成测试
├── temp_tests/              # 临时测试脚本
└── sigma-rules/             # Sigma规则库（Git Submodule）
```

**目录说明**：
- **根目录**：核心代码模块，直接导入使用
- **scripts/**：配置和管理脚本（规则导入、Detector创建等）
- **docs/**：所有文档（API参考、部署指南、进度总结等）
- **test/**：正式测试（pytest框架）
- **temp_tests/**：开发测试脚本
- **sigma-rules/**：Sigma规则库（Git Submodule，不直接提交）

## 🚀 快速开始

### 1. 克隆项目（包含Submodule）

```bash
git clone --recurse-submodules <repository-url>
# 或
git clone <repository-url>
git submodule update --init --recursive
```

### 2. 初始化索引

```python
from opensearch import initialize_indices
initialize_indices()
```

### 3. 开始使用

```python
from opensearch import store_events, run_data_analysis

# 存储事件
events = [{"event": {"kind": "event", "id": "evt-1", ...}, ...}]
result = store_events(events)

# 执行分析（检测 + 去重）
result = run_data_analysis(trigger_scan=True)
```

### 4. 标准导入

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

- **[API 参考文档](./docs/API_REFERENCE.md)** ⭐ - **前端调用者必读**
- **[部署指南](./docs/DEPLOYMENT.md)** ⭐ - **从零开始部署**
- **[进度总结](./docs/进度总结.md)** - 功能实现进度和关键发现

## 🛠️ 脚本工具

所有脚本位于 `scripts/` 目录：

- **[import_sigma_rules.py](./scripts/import_sigma_rules.py)** - 导入Sigma规则到OpenSearch
- **[setup_security_analytics.py](./scripts/setup_security_analytics.py)** - 配置Security Analytics Detector
- **[test_import_rules.py](./scripts/test_import_rules.py)** - 测试规则导入功能

## 🔧 环境变量

```bash
OPENSEARCH_NODE=https://localhost:9200
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=OpenSearch@2024!Dev
```

## 📦 依赖

### Python包

- `opensearch-py>=2.0.0`

安装方式：
```bash
uv add opensearch-py
# 或
pip install opensearch-py
```

### Sigma规则库（Git Submodule）

项目使用Git Submodule管理Sigma规则库：

```bash
# 首次克隆项目时，使用 --recurse-submodules
git clone --recurse-submodules <repository-url>

# 如果已经克隆了项目，初始化submodule
git submodule update --init --recursive

# 更新规则库
cd backend/app/services/opensearch/sigma-rules
git pull origin master
```

**常用操作**：
```bash
# 更新规则库
cd backend/app/services/opensearch/sigma-rules
git pull origin master
cd ../../..
git add backend/app/services/opensearch/sigma-rules
git commit -m "更新sigma规则库"
```

详细说明请参考：[Sigma规则库设置指南](./docs/SIGMA_RULES_SETUP.md)
