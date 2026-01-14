# OpenSearch索引与Mapping规范

## 文档目的

本文件定义 OpenSearch 的索引清单、命名规则、mapping 与生命周期策略，是本项目关于 OpenSearch 的唯一权威口径。

## 权威性声明

本文件是 OpenSearch 索引与 mapping 的唯一权威口径。任何设计文档不得复制本文件的字段表与 mapping 细节。

## 适用范围

- 中心机后端：`backend/`
- OpenSearch：中心机依赖服务

## 引用关系

- 数据对象与生命周期：`80-数据对象与生命周期.md`
- ECS 字段规范：`81-ECS字段规范.md`
- 告警数据规范：`83-告警数据规范.md`

## 1. 索引清单与命名规则

### 1.1 索引清单（运行时必须存在）

| 索引模式 | 索引名示例 | 数据对象 | 文档ID | 用途 |
|---|---|---|---|---|
| `ecs-events-YYYY-MM-DD` | `ecs-events-2026-01-14` | Telemetry | `event.id` | 事实检索、检测输入、证据回溯 |
| `raw-findings-YYYY-MM-DD` | `raw-findings-2026-01-14` | Raw Finding | `event.id` | 原始告警审计、融合输入 |
| `canonical-findings-YYYY-MM-DD` | `canonical-findings-2026-01-14` | Canonical Finding | `event.id` | 规范告警检索、溯源与入图主输入 |
| `analysis-tasks-YYYY-MM-DD` | `analysis-tasks-2026-01-14` | Trace Task | `task.id` | 任务状态、进度与任务级结果 |
| `client-registry` | `client-registry` | Client Registry | `client.id` | 客户机注册与轮询状态 |

索引命名与创建逻辑以代码为准：

- 索引命名：`backend/app/services/opensearch/index.py:get_index_name()`
- 索引创建：`backend/app/services/opensearch/client.py:ensure_index()`
- mapping 定义：`backend/app/services/opensearch/mappings.py`

### 1.2 命名规则（必须遵守）

1. 所有按日滚动索引统一采用 UTC 日期后缀：`YYYY-MM-DD`。  
2. 索引名禁止使用点号日期（例如 `2026.01.14`），避免 Security Analytics 的 pattern 解析问题。  
3. `client-registry` 为固定索引名，不按日滚动。  

### 1.3 索引 settings（固定）

中心机创建索引时写死以下 settings：

- `number_of_shards=1`
- `number_of_replicas=0`

该行为由 `backend/app/services/opensearch/client.py:ensure_index()` 固定实现。

## 2. Mapping 约束

本项目使用“核心字段白名单 mapping”的方式稳定检索与过滤能力。mapping 的权威定义在：

- `backend/app/services/opensearch/mappings.py`

下文对 mapping 做可读化展开，字段名与类型必须与代码一致。

### 2.1 `ecs-events-*`（Telemetry）

| 字段 | 类型 |
|---|---|
| `@timestamp` | `date` |
| `ecs.version` | `keyword` |
| `event.id` | `keyword` |
| `event.kind` | `keyword` |
| `event.category` | `keyword` |
| `event.type` | `keyword` |
| `event.action` | `keyword` |
| `event.module` | `keyword` |
| `event.dataset` | `keyword` |
| `event.created` | `date` |
| `event.ingested` | `date` |
| `event.original` | `text`（`index=false`） |
| `host.id` | `keyword` |
| `host.name` | `keyword` |
| `user.id` | `keyword` |
| `user.name` | `keyword` |
| `process.entity_id` | `keyword` |
| `process.pid` | `long` |
| `process.parent.pid` | `long` |
| `process.name` | `keyword` |
| `process.command_line` | `text`（带 `keyword` 子字段） |
| `source.ip` | `ip` |
| `source.port` | `long` |
| `destination.ip` | `ip` |
| `destination.port` | `long` |
| `network.transport` | `keyword` |
| `network.direction` | `keyword` |
| `dns.question.name` | `text`（带 `keyword` 子字段） |
| `file.path` | `keyword` |
| `file.hash.sha256` | `keyword` |
| `session.id` | `keyword` |
| `message` | `text` |

### 2.2 `raw-findings-*`（Raw Finding）

| 字段 | 类型 |
|---|---|
| `@timestamp` | `date` |
| `ecs.version` | `keyword` |
| `event.id` | `keyword` |
| `event.kind` | `keyword` |
| `event.category` | `keyword` |
| `event.type` | `keyword` |
| `event.action` | `keyword` |
| `event.dataset` | `keyword` |
| `event.severity` | `integer` |
| `event.created` | `date` |
| `event.ingested` | `date` |
| `rule.id` | `keyword` |
| `rule.name` | `keyword` |
| `rule.version` | `keyword` |
| `rule.ruleset` | `keyword` |
| `threat.tactic.id` | `keyword` |
| `threat.tactic.name` | `keyword` |
| `threat.technique.id` | `keyword` |
| `threat.technique.name` | `keyword` |
| `custom.finding.stage` | `keyword` |
| `custom.finding.providers` | `keyword` |
| `custom.finding.fingerprint` | `keyword` |
| `custom.confidence` | `float` |
| `custom.evidence.event_ids` | `keyword` |
| `host.id` | `keyword` |
| `host.name` | `keyword` |
| `user.id` | `keyword` |
| `user.name` | `keyword` |
| `process.entity_id` | `keyword` |
| `source.ip` | `ip` |
| `destination.ip` | `ip` |
| `destination.port` | `long` |
| `dns.question.name` | `text`（带 `keyword` 子字段） |
| `file.path` | `keyword` |
| `file.hash.sha256` | `keyword` |
| `message` | `text` |

### 2.3 `canonical-findings-*`（Canonical Finding）

Canonical Finding mapping 与 Raw Finding 保持同构（见 `backend/app/services/opensearch/mappings.py:canonical_findings_mapping`），区别在于：

- `event.dataset` 固定为 `finding.canonical`；
- `custom.finding.stage` 固定为 `canonical`；
- `custom.finding.providers` 为多来源去重合并后的数组；
- `custom.confidence` 为融合阶段计算得到的 0–1 浮点数；
- `event.id` 与 `custom.finding.fingerprint` 的生成规则见 `83-告警数据规范.md`。

### 2.4 `client-registry`（客户机注册表）

| 字段 | 类型 |
|---|---|
| `@timestamp` | `date` |
| `client.id` | `keyword` |
| `client.version` | `keyword` |
| `client.token_hash` | `keyword` |
| `client.listen_url` | `keyword` |
| `client.capabilities.falco` | `boolean` |
| `client.capabilities.suricata` | `boolean` |
| `client.capabilities.filebeat` | `boolean` |
| `host.id` | `keyword` |
| `host.name` | `keyword` |
| `poll.last_seen` | `date` |
| `poll.status` | `keyword` |
| `poll.last_error` | `text` |
| `cursor.value` | `keyword` |

### 2.5 `analysis-tasks-*`（溯源任务）

| 字段 | 类型 |
|---|---|
| `@timestamp` | `date` |
| `task.id` | `keyword` |
| `task.status` | `keyword` |
| `task.progress` | `integer` |
| `task.target.node_uid` | `keyword` |
| `task.window.start_ts` | `date` |
| `task.window.end_ts` | `date` |
| `task.started_at` | `date` |
| `task.finished_at` | `date` |
| `task.error` | `text` |
| `task.result.summary` | `text` |
| `task.result.ttp_similarity.attack_tactics` | `keyword` |
| `task.result.ttp_similarity.attack_techniques` | `keyword` |
| `task.result.ttp_similarity.similar_apts` | `nested` |
| `task.result.trace.updated_edges` | `integer` |
| `task.result.trace.path_edges` | `integer` |

## 3. 生命周期策略（固定口径）

索引保留周期的权威口径见：`80-数据对象与生命周期.md`。

本项目在课程演示环境中采用“按日滚动索引 + 定期清理旧索引”的方式执行保留策略。具体执行步骤在运维文档中给出：

- `../../90-运维与靶场/95-重置复现与排障.md`

## 4. Security Analytics 相关配置（固定）

### 4.1 检测输入索引

Security Analytics detector 的扫描输入索引模式固定为：

- `ecs-events-*`

### 4.2 Findings 的落地方式

Security Analytics 产生的 findings 不直接进入 Canonical Finding。中心机固定执行以下流程：

1. 从 Security Analytics findings API 拉取 findings；
2. 将 findings 转换为 ECS Raw Finding（`event.dataset="finding.raw.security_analytics"`）；
3. 通过 `store_events()` 写入 `raw-findings-*`；
4. 对 `raw-findings-*` 执行融合去重，生成 `canonical-findings-*`。

相关实现入口：

- `backend/app/services/opensearch/analysis.py:run_security_analytics()`
- `backend/app/services/opensearch/analysis.py:deduplicate_findings()`

### 4.3 Detector 数量约束（必须满足）

本项目运行时必须只存在一个 detector。  
中心机对 detector 的选择逻辑固定为“读取 detectors 搜索接口返回的第一条记录”（见 `backend/app/services/opensearch/analysis.py:_get_detector_id()`），因此必须通过运维步骤保证 detector 唯一。

## 5. 运维脚本入口

本项目的脚本入口位于：

- `backend/app/services/opensearch/scripts/`

固定使用以下脚本完成部署与验证：

- Sigma 规则导入：`import_sigma_rules.py`（固定使用 `--auto`）
- Security Analytics detector 创建：`setup_security_analytics.py`
- 端到端自检：`test_e2e_analysis.py`
