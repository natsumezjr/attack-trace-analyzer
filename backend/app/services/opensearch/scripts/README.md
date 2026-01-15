# OpenSearch Scripts 使用指南

## 核心脚本

### 数据生成

#### `consolidated_data_generator.py` - 统一数据生成脚本（推荐使用）

**功能**：
- 生成大量测试events（包含横向移动、端口扫描、权限提升等）
- 支持生成correlation测试数据
- 优化的批量写入，避免OOM
- 自动验证生成的数据

**使用方法**：
```bash
# 生成200个events（默认）
uv run python consolidated_data_generator.py

# 生成指定数量的events
uv run python consolidated_data_generator.py --count 500

# 只生成横向移动数据
uv run python consolidated_data_generator.py --type lateral-movement --count 100

# 生成correlation测试数据
uv run python consolidated_data_generator.py --correlation-test
```

#### `generate_test_events.py` - 旧版数据生成脚本（已弃用）

**状态**：已弃用，功能已合并到 `consolidated_data_generator.py`

**建议**：使用 `consolidated_data_generator.py` 替代

---

### 检查与诊断

#### `consolidated_check.py` - 统一检查脚本（推荐使用）

**功能**：
- 检查OpenSearch集群健康状态
- 检查JVM内存使用情况
- 检查detectors状态
- 检查findings类型分布
- 检查events分布

**使用方法**：
```bash
# 检查所有
uv run python consolidated_check.py

# 只检查健康状态
uv run python consolidated_check.py --health

# 只检查findings
uv run python consolidated_check.py --findings

# 只检查detectors
uv run python consolidated_check.py --detectors

# 只检查events
uv run python consolidated_check.py --events

# 只检查JVM内存
uv run python consolidated_check.py --jvm
```

---

### Security Analytics 管理

#### `setup_security_analytics.py` - 设置Security Analytics

**功能**：
- 创建detectors
- 创建多个detectors（dns, network, linux）

**使用方法**：
```bash
# 创建默认detector
uv run python setup_security_analytics.py

# 创建多个detectors
uv run python setup_security_analytics.py --multiple
```

#### `delete_detectors.py` - 删除detectors

**功能**：
- 列出所有detectors
- 删除指定类型的detectors
- 删除所有detectors

**使用方法**：
```bash
# 列出所有detectors
uv run python delete_detectors.py --list-only

# 删除所有detectors
uv run python delete_detectors.py --yes

# 删除指定类型的detectors
uv run python delete_detectors.py --type dns --yes
```

#### `create_findings_correlation_rules.py` - 创建findings correlation rules

**功能**：
- 创建针对findings的correlation rules
- 确保dashboard能显示correlations

**使用方法**：
```bash
uv run python create_findings_correlation_rules.py
```

#### `delete_correlation_rules.py` - 删除correlation rules

**功能**：
- 列出所有correlation rules
- 删除所有correlation rules（或指定名称的规则）

**使用方法**：
```bash
# 列出所有rules
uv run python delete_correlation_rules.py --list-only

# 删除所有rules
uv run python delete_correlation_rules.py --yes

# 删除指定名称的rule
uv run python delete_correlation_rules.py --name "Port Scanning Detection" --yes
```

---

### 其他工具脚本

#### `check_rules_stats.py` - 检查规则统计

**功能**：
- 查询Security Analytics规则统计
- 显示规则数量、分类等

**使用方法**：
```bash
uv run python check_rules_stats.py
```

#### `optimize_bulk_write.py` - 优化的批量写入

**功能**：
- 分批写入events（避免OOM）
- 减少refresh频率
- 临时调整refresh_interval

**使用方法**：
```python
from app.services.opensearch.scripts.optimize_bulk_write import store_events_optimized
store_events_optimized(events, batch_size=300, refresh_after=True)
```

#### `cleanup_old_data.py` - 统一的数据清理脚本（推荐使用）

**功能**：
- 删除 OpenSearch 中的旧 events（按时间范围）
- 删除 OpenSearch 中的旧 findings（按时间范围）
- 删除 Neo4j 中的旧图数据（按时间范围）
- 支持删除所有数据或指定天数前的数据
- 显示清理前后的数据统计

**使用方法**：
```bash
# 删除7天前的所有数据（默认）
uv run python cleanup_old_data.py --days 7

# 删除所有数据（危险！）
uv run python cleanup_old_data.py --all --yes

# 只删除events
uv run python cleanup_old_data.py --days 7 --only-events --yes

# 只删除findings
uv run python cleanup_old_data.py --days 7 --only-findings --yes

# 只删除Neo4j数据
uv run python cleanup_old_data.py --days 7 --only-neo4j --yes
```

---

## 已删除的脚本（功能已合并）

以下脚本已被删除，功能已合并到新的统一脚本中：

- `create_correlation_test_data.py` → 合并到 `consolidated_data_generator.py`
- `create_matching_events.py` → 合并到 `consolidated_data_generator.py`
- `check_correlation_history.py` → 合并到 `consolidated_check.py`
- `check_events_distribution.py` → 合并到 `consolidated_check.py`
- `check_findings_detailed.py` → 合并到 `consolidated_check.py`
- `check_findings_types.py` → 合并到 `consolidated_check.py`
- `check_opensearch_health.py` → 合并到 `consolidated_check.py`
- `check_why_only_dns_findings.py` → 合并到 `consolidated_check.py`
- `verify_events.py` → 合并到 `consolidated_data_generator.py`
- `trigger_and_check_correlations.py` → 功能已整合
- `trigger_correlation_engine.py` → 功能已整合
- `query_correlations_for_dashboard.py` → 功能已整合
- `run_detection_and_check.py` → 功能已整合
- `create_correlation_rule_example.py` → 功能已整合
- `create_simple_correlation_rules.py` → 功能已整合到 `create_findings_correlation_rules.py`
- `test_findings_correlation.py` → 功能已整合

---

## 快速开始

### 1. 生成测试数据

```bash
cd backend
uv run python app/services/opensearch/scripts/consolidated_data_generator.py --count 200
```

### 2. 检查系统状态

```bash
uv run python app/services/opensearch/scripts/consolidated_check.py
```

### 3. 设置Security Analytics

```bash
uv run python app/services/opensearch/scripts/setup_security_analytics.py --multiple
```

### 4. 创建correlation rules

```bash
uv run python app/services/opensearch/scripts/create_findings_correlation_rules.py
```

---

## 注意事项

1. **OOM问题**：如果遇到OOM，确保JVM堆内存至少2GB（见 `docker-compose.yml`）
2. **批量写入**：大量数据会自动使用分批写入，避免OOM
3. **Refresh频率**：批量写入时会临时调整refresh_interval，减少内存压力
