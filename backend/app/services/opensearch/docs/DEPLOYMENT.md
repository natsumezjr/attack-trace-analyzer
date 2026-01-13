# OpenSearch Security Analytics 部署指南

> **从零开始部署 OpenSearch Security Analytics 集成**

本文档详细说明如何从零开始部署 OpenSearch Security Analytics 集成，包括环境准备、索引初始化、规则导入、Detector创建等步骤。

---

## 📋 前置要求

### 1. OpenSearch 服务

- **版本**: OpenSearch 3.4.0 或更高
- **插件**: 
  - `security-analytics` 插件已安装
  - `alerting` 插件已安装（Security Analytics 依赖）

**检查插件是否安装**：
```bash
curl -k -u admin:OpenSearch@2024!Dev https://localhost:9200/_cat/plugins
```

应该看到：
```
opensearch-alerting
opensearch-security-analytics
```

### 2. Python 环境

- Python 3.8+
- 已安装 `opensearch-py` 包

**安装依赖**：
```bash
cd backend
uv add opensearch-py
# 或
pip install opensearch-py
```

### 3. 环境变量配置

确保以下环境变量已设置：

```bash
# Windows PowerShell
$env:OPENSEARCH_NODE="https://localhost:9200"
$env:OPENSEARCH_USERNAME="admin"
$env:OPENSEARCH_PASSWORD="OpenSearch@2024!Dev"

# Linux/Mac
export OPENSEARCH_NODE="https://localhost:9200"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="OpenSearch@2024!Dev"
```

---

## 🚀 部署步骤

### 步骤 1：初始化索引

**目的**：创建所有需要的索引（ecs-events、raw-findings、canonical-findings等）

**操作**：
```python
from opensearch import initialize_indices

# 创建所有索引
initialize_indices()
print("✅ 索引初始化完成")
```

**或者使用命令行**：
```bash
cd backend
uv run python -c "from opensearch import initialize_indices; initialize_indices(); print('✅ 索引初始化完成')"
```

**验证**：
```python
from opensearch import get_client, INDEX_PATTERNS, get_index_name
from datetime import datetime

client = get_client()
today = datetime.now()

# 检查索引是否存在
indices = [
    get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today),
    get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today),
    get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today),
]

for idx in indices:
    exists = client.indices.exists(index=idx)
    print(f"{idx}: {'✅ 存在' if exists else '❌ 不存在'}")
```

---

### 步骤 2：获取 Sigma 规则库（可选）

**目的**：获取Sigma规则库，用于Security Analytics检测

**说明**：
- 如果不使用Security Analytics检测，可以跳过此步骤
- Sigma规则库包含4000+个规则文件，**不直接提交到git仓库**
- 需要手动获取规则库

**操作**：

**方式1：使用Git Submodule（推荐，已配置）**

项目已配置git submodule：

```bash
# 初始化submodule（首次克隆项目后）
git clone --recurse-submodules <repository-url>
# 或
git clone <repository-url>
git submodule update --init --recursive

# 更新规则库
cd backend/opensearch/sigma-rules
git pull origin master
cd ../../..
git add backend/opensearch/sigma-rules
git commit -m "更新sigma规则库"
```

**方式2：手动克隆**

```bash
cd backend/opensearch
git clone https://github.com/SigmaHQ/sigma.git sigma-rules
```

**方式3：下载ZIP**

从 [SigmaHQ/sigma releases](https://github.com/SigmaHQ/sigma/releases) 下载最新版本并解压到 `backend/opensearch/sigma-rules` 目录。

**验证**：
```bash
cd backend/opensearch/sigma-rules
ls rules/  # 应该看到windows、linux、network等目录
```

### 步骤 3：导入 Sigma 规则（可选）

**目的**：将规则导入到OpenSearch Security Analytics

**说明**：
- 需要先完成步骤2（获取规则库）
- 建议按类别导入，避免一次性导入过多规则

**操作**：
```bash
cd backend/opensearch/scripts

# 查看可用的规则类别
python import_sigma_rules.py --list

# 导入特定类别（推荐）
python import_sigma_rules.py --category dns
python import_sigma_rules.py --category windows
python import_sigma_rules.py --category network

# 或者导入特定ATT&CK技术的规则
python import_sigma_rules.py --attack-id T1055

# 预览将要导入的规则（不实际导入）
python import_sigma_rules.py --category dns --dry-run
```

**验证**：
```python
from opensearch import get_client

client = get_client()
response = client.transport.perform_request(
    'POST',
    '/_plugins/_security_analytics/rules/_search',
    body={"size": 10}
)
rules = response.get('hits', {}).get('hits', [])
print(f"✅ 已导入 {len(rules)} 个规则")
```

---

### 步骤 3：创建 Detector（可选）

**目的**：创建Security Analytics检测器，用于扫描事件并生成findings

**说明**：
- 如果不使用Security Analytics检测，可以跳过此步骤
- Detector会自动创建对应的Workflow和Monitor
- 需要先确保索引已创建（步骤1）

**操作**：
```bash
cd backend/opensearch
python setup_security_analytics.py
```

**脚本会自动**：
1. 检查Security Analytics插件是否可用
2. 检查索引是否存在（不存在则创建）
3. 获取预打包规则
4. 创建Detector（如果不存在）
5. 验证Detector状态

**输出示例**：
```
[OK] Security Analytics 插件可用
[INFO] 检查索引: ecs-events-2026-01-13
[OK] 索引已存在
[INFO] 获取预打包DNS规则...
[INFO] 找到 5 个预打包DNS规则
[INFO] 创建Detector: ecs-events-detector
[OK] Detector创建成功
[INFO] Detector ID: TuBJt5sBYd8aacU-nv_U
[OK] Detector已启用
```

**验证**：
```python
from opensearch import get_client

client = get_client()
response = client.transport.perform_request(
    'POST',
    '/_plugins/_security_analytics/detectors/_search',
    body={"size": 10}
)
detectors = response.get('hits', {}).get('hits', [])
for detector in detectors:
    print(f"Detector: {detector['_source'].get('name')}")
    print(f"  状态: {detector['_source'].get('enabled', False)}")
    print(f"  类型: {detector['_source'].get('detector_type')}")
```

---

### 步骤 5：生成测试数据（可选）

**目的**：生成测试数据，验证整个流程是否正常工作

**操作**：
```bash
cd backend
python generate_test_data.py
```

**脚本会**：
1. 生成60个DNS事件（包括可疑和正常的）
2. 存储到 `ecs-events-*` 索引
3. 显示存储统计

**输出示例**：
```
============================================================
生成测试数据
============================================================

生成 60 个测试事件...
  - DNS事件: 40 个（其中可疑: 20 个）
  - 进程事件: 20 个

存储事件到OpenSearch...
  - 成功存储: 60 个
  - 跳过（重复）: 0 个

[OK] 测试数据生成成功！
```

---

### 步骤 6：验证完整流程

**目的**：验证存储和分析流程是否正常工作

**操作**：
```python
from opensearch import store_events, run_data_analysis
from datetime import datetime

# 1. 测试存储
test_events = [{
    "ecs": {"version": "9.2.0"},
    "@timestamp": datetime.now().isoformat() + "Z",
    "event": {
        "id": "test-001",
        "kind": "event",
        "created": datetime.now().isoformat() + "Z",
        "category": ["network"],
        "type": ["info"],
    },
    "host": {
        "id": "h-test",
        "name": "test-host"
    },
    "message": "测试事件",
}]

storage_result = store_events(test_events)
print(f"✅ 存储测试: {storage_result['success']} 个成功")

# 2. 测试分析
analysis_result = run_data_analysis(trigger_scan=True)
print(f"✅ 检测成功: {analysis_result['detection']['success']}")
print(f"✅ 规范告警: {analysis_result['deduplication']['canonical']} 个")
```

**或者使用测试脚本**：
```bash
cd backend/opensearch/temp_tests

# 测试存储功能
uv run python test_storage_with_clear.py

# 测试去重功能
uv run python test_deduplication.py

# 测试完整流程
uv run python test_full_flow.py
```

---

## 📊 部署验证清单

完成部署后，检查以下项目：

- [ ] ✅ OpenSearch服务正常运行
- [ ] ✅ Security Analytics插件已安装
- [ ] ✅ Alerting插件已安装
- [ ] ✅ 环境变量已配置
- [ ] ✅ 索引已创建（ecs-events、raw-findings、canonical-findings）
- [ ] ✅ Sigma规则库已获取（如果使用Security Analytics）
- [ ] ✅ Sigma规则已导入（如果使用Security Analytics）
- [ ] ✅ Detector已创建（如果使用Security Analytics）
- [ ] ✅ 测试数据存储成功
- [ ] ✅ 分析流程运行正常

---

## 🔧 常见问题

### Q1: Security Analytics插件未安装怎么办？

**A**: 需要安装Security Analytics插件：

```bash
# 在OpenSearch安装目录执行
bin/opensearch-plugin install security-analytics
# 然后重启OpenSearch服务
```

### Q2: 创建Detector时提示索引不存在？

**A**: 先执行步骤1初始化索引：
```python
from opensearch import initialize_indices
initialize_indices()
```

### Q3: 导入规则时提示格式错误？

**A**: 某些Sigma规则可能与OpenSearch Security Analytics格式不完全兼容，这是正常的。脚本会自动跳过不兼容的规则。

### Q4: 如何查看已导入的规则？

**A**: 
```python
from opensearch import get_client

client = get_client()
response = client.transport.perform_request(
    'POST',
    '/_plugins/_security_analytics/rules/_search',
    body={"size": 100}
)
rules = response.get('hits', {}).get('hits', [])
for rule in rules:
    print(rule['_source'].get('title'))
```

### Q5: 如何查看Detector状态？

**A**:
```python
from opensearch import get_client

client = get_client()
response = client.transport.perform_request(
    'POST',
    '/_plugins/_security_analytics/detectors/_search',
    body={"size": 10}
)
detectors = response.get('hits', {}).get('hits', [])
for detector in detectors:
    print(f"名称: {detector['_source'].get('name')}")
    print(f"状态: {'启用' if detector['_source'].get('enabled') else '禁用'}")
```

---

## 📚 相关文档

- [API参考文档](./API_REFERENCE.md) - 详细的API使用说明
- [进度总结](./进度总结.md) - 完整的功能实现进度
- [README](./README.md) - 模块概述和快速开始

---

## 🎯 下一步

部署完成后，你可以：

1. **开始使用存储和分析功能**：
   ```python
   from opensearch import store_events, run_data_analysis
   ```

2. **查看API参考文档**：[API_REFERENCE.md](./API_REFERENCE.md)

3. **运行测试脚本**：验证各个功能模块

4. **集成到前端**：调用存储和分析接口
