# OpenSearch Security Analytics - Correlation Rule 创建和可视化指南

本指南将教你如何针对数据创建 correlation rule，并在 OpenSearch Dashboards 中可视化 correlations。

## 目录

1. [前置条件](#前置条件)
2. [创建 Correlation Rule](#创建-correlation-rule)
3. [可视化 Correlations](#可视化-correlations)
4. [示例：针对 Findings 创建规则](#示例针对-findings-创建规则)
5. [常见问题](#常见问题)

---

## 前置条件

1. **OpenSearch Security Analytics 已安装并启用**
2. **已有 Security Analytics Findings**（在 `raw-findings-*` 索引中）
3. **访问 OpenSearch Dashboards 的权限**

---

## 创建 Correlation Rule

### 方法1：通过 OpenSearch Dashboards UI

#### 步骤1：访问 Correlation Rules

1. 登录 OpenSearch Dashboards
2. 在主菜单中选择 **Security Analytics**
3. 在左侧菜单中点击 **Correlation rules**

#### 步骤2：创建新规则

1. 点击 **Create correlation rule** 按钮
2. 在 **Correlation rule details** 部分输入规则名称

#### 步骤3：配置查询（至少需要2个查询）

对于每个查询，需要配置：

- **Select Index**: 选择索引或索引模式
  - 对于 Findings: 选择 `raw-findings-*`
  - 对于 Events: 选择 `ecs-events-*`
  
- **Log Type**: 指定日志类型
  - 例如: `process`, `network`, `file`, `dns`, `authentication` 等
  
- **Field and Value**: 选择字段并输入值
  - 例如: `event.severity` >= `50`
  - 例如: `host.name` = `host-100`
  - 例如: `threat.tactic.name` = `Lateral Movement`
  
- **Add field**: 点击可添加更多字段条件

#### 步骤4：添加更多查询（可选）

- 点击 **Add query** 添加第三个、第四个查询等
- 每个查询应该针对不同的日志源或不同的条件

#### 步骤5：设置时间窗口（可选）

Correlation 引擎会在指定的时间窗口内评估 findings。默认是 5 分钟。

可以通过 Cluster Settings API 调整：

```json
PUT /_cluster/settings
{
  "transient": {
    "plugins.security_analytics.correlation_time_window": "30m"
  }
}
```

#### 步骤6：保存规则

点击 **Create correlation rule** 保存规则。

---

### 方法2：通过 API 创建

#### API 端点

```
POST /_plugins/_security_analytics/correlation/rules
```

#### 请求体格式

```json
{
  "name": "规则名称",
  "description": "规则描述",
  "tags": ["tag1", "tag2"],
  "correlate": [
    {
      "index": "raw-findings-*",
      "category": "process",
      "query": "event.severity:>=50 AND _exists_:host.name"
    },
    {
      "index": "raw-findings-*",
      "category": "network",
      "query": "event.severity:>=50 AND _exists_:host.name"
    }
  ]
}
```

#### Python 示例

```python
from app.services.opensearch.internal import get_client, INDEX_PATTERNS

client = get_client()
findings_index_pattern = f"{INDEX_PATTERNS['RAW_FINDINGS']}-*"

correlation_rule = {
    "name": "Same Host Multiple Threats",
    "description": "检测同一主机上的多个威胁findings",
    "tags": ["multi-threat", "attack.detection"],
    "correlate": [
        {
            "index": findings_index_pattern,
            "category": "process",
            "query": "event.severity:>=50 AND _exists_:host.name"
        },
        {
            "index": findings_index_pattern,
            "category": "network",
            "query": "event.severity:>=50 AND _exists_:host.name"
        }
    ]
}

response = client.transport.perform_request(
    'POST',
    '/_plugins/_security_analytics/correlation/rules',
    body=correlation_rule
)

rule_id = response.get('_id')
print(f"规则创建成功，ID: {rule_id}")
```

---

## 可视化 Correlations

### 步骤1：访问 Correlation Graph

1. 在 OpenSearch Dashboards 中，选择 **Security Analytics**
2. 从左侧菜单选择 **Correlations**

### 步骤2：理解图形元素

#### 节点（Nodes）

- 每个节点代表一个 security finding
- **节点边框颜色**表示严重性级别：
  - 🔴 **红色**: Critical（严重）
  - 🟠 **橙色**: High（高）
  - 🟡 **黄色**: Medium（中）
  - 🔵 **蓝色**: Low（低）
  - 🟢 **绿色**: Informational（信息）
- **节点内的三个字母缩写**表示日志类型（如 `PRC` = Process, `NET` = Network）

#### 边（Edges/Lines）

- 连接节点的线表示 findings 之间的 correlations
- **线的粗细**表示 correlation 的强度：
  - **粗线**: 强 correlation
  - **细线**: 弱 correlation

### 步骤3：使用图形功能

#### 过滤 Findings

- **Severity（严重性）**: 使用下拉菜单按严重性过滤
- **Log types（日志类型）**: 使用下拉菜单按日志类型过滤
- **Time Range（时间范围）**: 调整时间过滤器，然后点击 **Refresh** 更新图形

#### 重置过滤器

点击 **Reset filters** 恢复到默认视图（显示所有 findings）

#### 缩放和平移

- 使用鼠标滚轮缩放
- 拖拽图形进行平移

#### 查看详细信息

点击一个 finding 节点：
- 右侧会显示信息卡片
- 显示：
  - 严重性级别
  - Correlation 分数（correlation 强度）
  - 生成该 finding 的检测规则
  - 用于关联 findings 的 correlation rule

#### 聚焦特定 Finding

选择一个 finding 后，图形会更新为只显示：
- 选中的 finding
- 与其直接相关的 correlated findings

---

## 示例：针对 Findings 创建规则

### 示例1：同一主机的多个威胁

**场景**: 检测同一主机上出现的多个高严重性 findings

**规则配置**:
- **Query 1**:
  - Index: `raw-findings-*`
  - Log Type: `process`
  - Query: `event.severity:>=50 AND _exists_:host.name`
  
- **Query 2**:
  - Index: `raw-findings-*`
  - Log Type: `network`
  - Query: `event.severity:>=50 AND _exists_:host.name`

**预期结果**: 如果同一主机在时间窗口内同时出现 process 和 network 类型的高严重性 findings，它们会被关联。

### 示例2：横向移动检测

**场景**: 检测横向移动攻击链

**规则配置**:
- **Query 1**:
  - Index: `raw-findings-*`
  - Log Type: `network`
  - Query: `tags:attack.lateral_movement OR threat.tactic.name:Lateral Movement`
  
- **Query 2**:
  - Index: `raw-findings-*`
  - Log Type: `process`
  - Query: `tags:attack.execution OR threat.tactic.name:Execution`

**预期结果**: 如果网络横向移动 finding 后跟进程执行 finding，它们会被关联。

### 示例3：最简单的规则（确保能找到 correlations）

**场景**: 匹配任意两个 findings（用于测试）

**规则配置**:
- **Query 1**:
  - Index: `raw-findings-*`
  - Log Type: `process`
  - Query: `*` 或 `_exists_:event.severity`
  
- **Query 2**:
  - Index: `raw-findings-*`
  - Log Type: `network`
  - Query: `*` 或 `_exists_:event.severity`

**预期结果**: 任何两个 findings（一个 process，一个 network）都会被关联。

---

## 常见问题

### Q1: Dashboard 显示 "No correlations found"

**可能原因**:
1. Correlation 引擎还未运行（需要等待几分钟）
2. Findings 之间不满足关联条件
3. 时间窗口不匹配
4. Correlation rules 的查询条件与 findings 的实际字段不匹配

**解决方案**:
1. 等待几分钟，然后刷新 dashboard
2. 在 dashboard 中调整时间范围（尝试最近 24 小时或更长时间）
3. 生成更多 findings（至少 2 个以上）
4. 检查 correlation rules 的查询条件是否与 findings 的实际字段匹配
5. 创建更简单的规则（如示例3）进行测试

### Q2: Correlation 引擎如何工作？

Correlation 引擎会：
1. 自动扫描 `raw-findings-*` 索引中的 findings
2. 根据 correlation rules 的查询条件匹配 findings
3. 在指定的时间窗口内评估 findings 之间的关联
4. 将 correlations 存储在 correlation-history 索引中
5. Dashboard 从 correlation-history 索引读取并显示

### Q3: 如何调整时间窗口？

使用 Cluster Settings API:

```json
PUT /_cluster/settings
{
  "transient": {
    "plugins.security_analytics.correlation_time_window": "30m"
  }
}
```

时间窗口格式: `数字 + 单位`（如 `5m`, `1h`, `30m`）

### Q4: 如何查看 correlation rules 列表？

**通过 UI**:
- Security Analytics → Correlation rules

**通过 API**:
```http
POST /_plugins/_security_analytics/correlation/rules/_search
{
  "query": {"match_all": {}},
  "size": 100
}
```

### Q5: 如何删除 correlation rule？

**通过 UI**:
- 在 Correlation rules 页面，点击规则旁边的删除按钮

**通过 API**:
```http
DELETE /_plugins/_security_analytics/correlation/rules/{rule_id}
```

### Q6: Correlation rules 应该针对 Events 还是 Findings？

**推荐**: 针对 **Findings**（`raw-findings-*` 索引）

**原因**:
- Dashboard 的 Correlation Graph 从 `raw-findings-*` 索引读取数据
- Findings 已经经过 Security Analytics 检测，包含威胁信息
- Correlation 引擎专门设计用于关联 findings

### Q7: 如何测试 correlation rule 是否能匹配 findings？

可以使用我们提供的测试脚本：

```bash
cd backend
uv run python app/services/opensearch/scripts/test_findings_correlation.py
```

这个脚本会：
1. 获取所有 findings
2. 测试每个 correlation rule 是否能匹配这些 findings
3. 显示匹配结果

---

## 最佳实践

1. **从简单规则开始**: 先创建简单的规则确保能找到 correlations，然后再创建复杂的规则
2. **使用有意义的名称**: 规则名称应该清楚地描述它检测的威胁场景
3. **合理设置时间窗口**: 根据你的数据生成频率调整时间窗口
4. **定期检查规则**: 确保规则仍然有效，删除不再需要的规则
5. **监控 correlation 结果**: 定期查看 Correlation Graph，了解威胁模式

---

## 相关资源

- [OpenSearch Security Analytics 官方文档](https://docs.opensearch.org/latest/security-analytics/)
- [创建 Correlation Rules 文档](https://docs.opensearch.org/3.1/security-analytics/sec-analytics-config/correlation-config)
- [Correlation Graph 使用指南](https://docs.opensearch.org/latest/security-analytics/usage/correlation-graph/)
- [Correlation Engine API 文档](https://docs.opensearch.org/latest/security-analytics/api-tools/correlation-eng/)

---

## 脚本工具

我们提供了以下脚本帮助你创建和管理 correlation rules:

1. **`create_findings_correlation_rules.py`**: 创建多个针对 findings 的规则
2. **`create_simple_correlation_rules.py`**: 创建最简单的规则（用于测试）
3. **`test_findings_correlation.py`**: 测试规则是否能匹配 findings
4. **`trigger_correlation_engine.py`**: 触发 correlation 引擎
5. **`query_correlations_for_dashboard.py`**: 查询 correlations 供 dashboard 显示

使用方法:
```bash
cd backend
uv run python app/services/opensearch/scripts/<script_name>.py
```
