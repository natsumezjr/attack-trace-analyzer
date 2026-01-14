# OpenSearch 模块规格说明书

## 1. 模块职责与边界

OpenSearch 模块负责中心机侧“事实/告警/任务元数据”的权威存储与检索能力，具体职责固定为：

1. **索引体系**：定义索引命名、按日滚动策略、生命周期保留策略；
2. **入库路由**：根据 `event.kind` 与 `event.dataset` 将文档写入正确索引；
3. **字段处理**：对 ECS 文档执行三时间字段处理、扁平键兼容、基础校验；
4. **Store-first 检测**：触发 OpenSearch Security Analytics 扫描 Telemetry 并产出 Findings；
5. **融合去重**：将 Raw Findings 融合为 Canonical Findings 并写回 OpenSearch；
6. **任务存储**：保存溯源任务的状态与元数据，供前端轮询。

本模块不负责：

- Neo4j 图谱建模与查询（见 `32-Neo4j模块规格说明书.md`、`52-实体图谱规范.md`）；
- 溯源算法与结果写回（见 `33-Analysis模块规格说明书.md`）；
- 客户机采集与接口（见 `54-客户机-中心机接口规范.md`）。

## 2. 索引体系与命名

### 2.1 索引清单（系统运行时必须存在）

| 索引模式 | 数据对象 | 写入方 | 用途 |
|---|---|---|---|
| `ecs-events-YYYY-MM-DD` | Telemetry | 中心机流水线 Step 2 | 事实事件检索、Store-first 检测输入 |
| `raw-findings-YYYY-MM-DD` | Raw Findings | 中心机流水线 Step 3 | 原始告警审计、融合输入 |
| `canonical-findings-YYYY-MM-DD` | Canonical Findings | 中心机流水线 Step 3 | 图谱与溯源的主输入 |
| `client-registry` | 客户机注册表 | 客户机注册 + 流水线更新 | 客户机列表、游标、在线状态 |
| `analysis-tasks-YYYY-MM-DD` | Trace Task | Analysis 模块 | 异步任务状态与进度轮询 |

> 说明：索引保留策略在第 6 节定义；ECS 字段口径在 `51-ECS字段规范.md` 定义。

### 2.2 索引命名规则（必须遵守）

1. 所有按日滚动的索引必须使用连字符日期：`YYYY-MM-DD`。  
2. 索引名不得出现点号日期（例如 `2026.01.13`），避免 Security Analytics 的 pattern 解析问题。  
3. `client-registry` 不按日滚动，索引名固定为 `client-registry`。

## 3. 入库路由与字段处理

### 3.1 路由规则（权威）

对每条输入文档，中心机必须按以下规则路由（伪代码表达）：

- 当 `event.kind == "event"`：写入 `ecs-events-*`
- 当 `event.kind == "alert"` 且 `event.dataset == "finding.canonical"`：写入 `canonical-findings-*`
- 当 `event.kind == "alert"` 且 `event.dataset != "finding.canonical"`：写入 `raw-findings-*`

### 3.2 三时间字段处理（必须执行）

中心机写入 OpenSearch 前必须保证三时间字段满足 `51-ECS字段规范.md`：

- `@timestamp`：主时间轴。若缺失，必须从 `event.created` 推导；若仍无法得到，中心机必须丢弃该文档。
- `event.created`：观察时间。若缺失，中心机必须回填为 `@timestamp`。
- `event.ingested`：入库时间。中心机必须覆盖为“当前入库时间”，不得使用上游携带值。

### 3.3 幂等与去重（必须满足）

1. 每条文档必须具备 `event.id`。  
2. 中心机写入必须按 `event.id` 幂等：同一 `event.id` 重复写入不得产生重复文档。  
3. 对于无法保证 `event.id` 稳定的上游输入，必须在进入中心机前或中心机 Step 2 中按 `51-ECS字段规范.md` 补齐稳定 `event.id`。

## 4. Store-first 检测（Security Analytics）

### 4.1 固定输入与输出

- 输入索引：`ecs-events-*`
- 输出对象：Security Analytics Findings（中心机必须拉取并转换成 ECS Raw Finding）
- 输出索引：`raw-findings-*`

### 4.2 Findings 转换（必须满足）

中心机从 Security Analytics 获取到的 Findings 必须转换为 ECS Finding 文档，并满足：

- `event.kind="alert"`
- `custom.finding.stage="raw"`
- 必须尽最大可能填充 `rule.*` 与 `threat.*`（Technique/Tactic 由规则标签映射得到；若缺失则写入占位值并在冲突汇总中记录）
- 必须写入 `custom.evidence.event_ids[]`，引用触发该 finding 的 Telemetry `event.id`

> 该转换规则的字段级细节归属于 `51-ECS字段规范.md` 的 Finding 章节。

## 5. Raw Findings → Canonical Findings（融合去重）

### 5.1 融合输入范围

融合输入为“指定时间窗内”的 Raw Findings。时间窗取值固定为 `TIME_WINDOW_MINUTES=3` 分钟，并用于计算 time_bucket。

### 5.2 指纹生成（必须一致）

对每条 Raw Finding 生成指纹 key：

```
{technique_id}|{host_id}|{entity_id}|{time_bucket}
```

其中：

- `technique_id`：取 `threat.technique.id`，缺失则为 `unknown`
- `host_id`：取 `host.id`，缺失则为 `unknown`
- `entity_id`：按固定优先级选择：
  1) `process.entity_id`
  2) `destination.ip`（若同时存在 `destination.domain`，则拼接 `ip|domain`）
  3) `file.hash.sha256`
  4) `unknown`
- `time_bucket = floor(@timestamp / (TIME_WINDOW_MINUTES * 60))`

将指纹 key 转换为可存储的 `custom.finding.fingerprint`：

- `custom.finding.fingerprint = "fp-" + sha1(fingerprint_key)`

### 5.3 Canonical 文档生成规则

对每个 fingerprint 分组：

- 当分组内包含多条 Raw Finding：生成 1 条 Canonical Finding，并合并字段：
  - `custom.finding.stage="canonical"`
  - `custom.finding.providers[]`：去重合并所有来源
  - `custom.evidence.event_ids[]`：去重合并证据引用
  - `event.severity`：取最大值
  - `custom.confidence`：按“来源数量”单调递增
- 当分组内只有 1 条 Raw Finding：复制该 finding 并按 Canonical 口径改写必要字段（stage/providers/fingerprint/dataset 等）。

Canonical Finding 的 `event.id` 生成规则固定为：

- `event.id = "canonical-" + sha256(fingerprint_key)[:16]`

并且必须满足：

- `event.kind="alert"`
- `event.dataset="finding.canonical"`
- 三时间字段处理规则同第 3.2 节

## 6. 保留策略与脚本

### 6.1 数据保留周期（固定）

保留周期的权威口径见：`50-数据库设计.md` 第 4 章。

### 6.2 初始化与运维脚本（入口）

OpenSearch 侧的初始化动作固定为：

1) 创建/确保索引存在（包含 mapping）。  
2) 配置 ISM policy 并绑定到对应索引模式。  
3) 配置 Security Analytics detector，并导入 Sigma 规则。  

脚本入口固定为以下文件：

- ISM policy 配置：`backend/app/services/opensearch/scripts/setup_index_management.py`
- Sigma 规则导入：`backend/app/services/opensearch/scripts/import_sigma_rules.py`
- Security Analytics detector 配置：`backend/app/services/opensearch/scripts/setup_security_analytics.py`
