# 数据分析模块使用说明

## 📋 功能概述

数据分析模块实现了两个核心功能：

1. **OpenSearch Security Analytics 检测**（Store-first 检测）
   - 从 `ecs-events-*` 索引读取事件
   - 使用 Sigma 规则检测异常
   - 将检测结果写入 `raw-findings-*` 索引

2. **告警融合去重**（Raw Findings → Canonical Findings）
   - 从 `raw-findings-*` 读取所有告警
   - 按指纹分组并合并重复告警
   - 输出到 `canonical-findings-*` 索引

## 🔧 API 接口

### POST /api/v1/analysis/run

触发数据分析流程。

**请求**：
```bash
curl -X POST http://localhost:3000/api/v1/analysis/run
```

**响应**：
```json
{
  "status": "ok",
  "message": "数据分析完成",
  "result": {
    "detection": {
      "success": true,
      "message": "Security Analytics 检测需要先配置 detector（当前为 MVP 版本）"
    },
    "deduplication": {
      "total": 10,        // Raw Findings 总数
      "merged": 8,        // 被合并的告警数量
      "canonical": 5,     // 生成的 Canonical Findings 数量
      "errors": 0         // 错误数量
    }
  }
}
```

## 🔑 核心函数

### `runDataAnalysis()`

主函数，执行完整的数据分析流程。

```typescript
import { runDataAnalysis } from '@/lib/opensearch/analysis';

const result = await runDataAnalysis();
// {
//   detection: { success, message },
//   deduplication: { total, merged, canonical, errors }
// }
```

### `deduplicateFindings()`

告警融合去重函数。

```typescript
import { deduplicateFindings } from '@/lib/opensearch/analysis';

const result = await deduplicateFindings();
// { total, merged, canonical, errors }
```

### `runSecurityAnalytics()`

触发 Security Analytics 检测（当前为 MVP 版本，需要配置）。

```typescript
import { runSecurityAnalytics } from '@/lib/opensearch/analysis';

const result = await runSecurityAnalytics();
// { success, message }
```

## 📊 指纹算法

告警融合使用指纹算法来识别重复告警：

```
指纹 = technique_id + host + (process_entity_id | dst_ip/domain | file_hash) + time_bucket
```

其中：
- `technique_id`: ATT&CK technique ID
- `host`: 主机 ID
- `entity_id`: 实体标识符（优先级：process_entity_id > dst_ip/domain > file_hash）
- `time_bucket`: 时间桶（`floor(@timestamp / 3分钟)`）

在相同时间窗口内，相同指纹的告警会被合并为一条 Canonical Finding。

## 🔄 合并规则

合并时：

1. **custom.finding.providers**: 追加所有来源引擎（wazuh/falco/suricata/opensearch-security-analytics）
2. **custom.evidence.event_ids**: 合并所有证据引用（去重）
3. **event.severity**: 取最大值
4. **custom.confidence**: 按来源数量上调（基础 0.5，每个来源 +0.15，最高 1.0）
5. **event.dataset**: 设置为 `finding.canonical`
6. **custom.finding.stage**: 设置为 `canonical`

## ⚠️ 注意事项

1. **Security Analytics 检测**：
   - 当前为 MVP 版本，需要先手动配置 OpenSearch Security Analytics 的 detector 和规则
   - 未来版本将实现自动调用 OSA API

2. **时间窗口**：
   - 默认时间窗口为 3 分钟（可在代码中调整 `TIME_WINDOW_MINUTES`）
   - 实验规模小建议使用较小的时间窗口（1-5 分钟）

3. **性能考虑**：
   - 查询时默认最多返回 10000 条 Raw Findings（可根据实际情况调整）
   - 对于大数据量，建议分批处理

## 📝 使用示例

### API 调用

```bash
curl -X POST http://localhost:3000/api/v1/analysis/run
```

### 代码调用

```typescript
import { runDataAnalysis } from '@/lib/opensearch';

const result = await runDataAnalysis();
console.log('检测结果:', result.detection);
console.log('去重结果:', result.deduplication);
```
