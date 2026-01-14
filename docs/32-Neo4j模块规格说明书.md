# Neo4j 模块规格说明书

## 1. 模块职责与边界

Neo4j 模块负责“实体关系图（Entity Graph）”的权威存储与图查询能力，具体职责固定为：

1. **Schema 管理**：创建并维持节点唯一约束与常用索引；
2. **入图写入**：将输入的 ECS 文档转换为节点/边，并写入 Neo4j；
3. **时间窗查询**：支持按时间窗查询边集合（供图可视化与算法使用）；
4. **图算法查询**：支持基于时间窗投影图的最短路（Neo4j GDS）；
5. **结果承载**：承载溯源任务写回的边属性，供后续“按节点查询溯源结果”。

本模块不负责：

- OpenSearch 的检测与融合（见 `31-OpenSearch模块规格说明书.md`）；
- 溯源算法的具体执行（见 `33-Analysis模块规格说明书.md`）；
- ECS 字段口径（见 `51-ECS字段规范.md`）。

## 2. Schema 与约束（与 52 对齐）

### 2.1 节点唯一约束（必须存在）

节点类型与唯一键由 `52-实体图谱规范.md` 定义。Neo4j 必须落地以下唯一约束（表达为“Label + 属性键”）：

| Label | 唯一键 |
|---|---|
| `Host` | `host.id` |
| `User` | `user.id` |
| `User` | `host.id + user.name` |
| `Process` | `process.entity_id` |
| `File` | `host.id + file.path` |
| `Domain` | `domain.name` |
| `IP` | `ip` |

> 说明：`User` 与 `File` 的复合键用于避免跨主机误合并；当存在 `user.id` 时优先使用 `user.id` 作为唯一键。

### 2.2 索引（必须存在）

为支撑展示与排障，Neo4j 必须为以下属性建立索引：

- `Host.host.name`
- `User.user.name`
- `Process.process.executable`
- `File.file.path`
- `Domain.domain.name`
- `IP.ip`

## 3. 写入：ECS → Graph

### 3.1 入图输入范围（严格）

Neo4j 入图只接受两类 ECS 文档：

1. Telemetry：`event.kind="event"`
2. Canonical Findings：`event.kind="alert"` 且 `event.dataset="finding.canonical"`

任何 Raw Findings（含传感器原始告警与 Security Analytics 原始 finding）不得直接入图。

### 3.2 入图边属性（必须写入）

每条入图边必须写入以下属性（字段名与来源以 `51/52` 为准）：

- `ts` 或 `@timestamp`：边的事件时间（字符串时间戳）
- `ts_float`：数值时间戳（秒，float），用于时间窗过滤与 GDS 投影
- `custom.evidence.event_ids[]`：证据事件引用列表
- `event.kind` / `event.dataset` / `event.id`：用于回溯与区分来源

当边来自 Canonical Finding 时，边必须额外写入：

- `is_alarm=true`
- `rule.*`、`threat.*`、`event.severity`、`custom.finding.*` 等字段（用于解释与可视化）

### 3.3 写入幂等边界

- 节点写入必须幂等（MERGE），以唯一键去重；
- 边写入是“按证据追加”的语义：边允许出现多条相同类型关系，但每条边必须携带其证据 `event.id` 与证据列表，便于后续去重/回放。

> 边去重属于 Analysis 的工作范围：在“展示层”与“任务结果写回层”通过属性与过滤实现干净展示。

## 4. 查询：可视化与算法的图查询

### 4.1 图查询能力清单（必须支持）

Neo4j 模块必须提供以下查询能力：

1. **告警边查询**：返回所有 `is_alarm=true` 的边集合；
2. **时间窗边查询**：给定 `[t_min, t_max]`（秒），返回时间窗内的边集合，并支持按关系类型过滤；
3. **时间窗最短路**：给定 `src_uid`、`dst_uid`、`[t_min, t_max]` 与风险权重表，返回时间窗内的加权最短路边序列。

### 4.2 后端对外 API 绑定（固定）

后端对外提供统一的图查询入口：

- `POST /api/v1/graph/query`

该接口支持以下动作：

- `alarm_edges`
- `edges_in_window`
- `shortest_path_in_window`

接口的请求/响应字段由后端实现固定，Neo4j 模块负责提供稳定的查询语义与返回结构（nodes/edges 的 uid、rtype、props）。

## 5. 结果写回：边属性规范

### 5.1 写回目标

溯源任务完成后，Analysis 模块把结果写回 Neo4j 的边属性。写回的目的固定为：

1. 让前端能在“按节点查询”时直接读到溯源结果；
2. 让“同一节点、同一时间窗”的任务结果可覆盖更新，避免历史结果造成展示混乱。

### 5.2 写回字段命名（固定前缀）

所有溯源写回字段必须使用统一前缀 `analysis.`，并且字段名使用点号分隔（Neo4j 属性名允许点号，写入时必须做 Cypher 反引号转义）。

写回字段集合固定为：

- `analysis.task_id`：字符串，当前写回对应的任务 ID
- `analysis.updated_at`：字符串，RFC3339
- `analysis.is_path_edge`：布尔，表示该边属于“关键路径”
- `analysis.risk_score`：浮点数，表示该边的风险评分
- `analysis.ttp.technique_ids[]`：字符串数组，表示该边关联的 Technique ID 集合
- `analysis.summary`：字符串，表示解释性摘要文本（用于报告与演示）

### 5.3 覆盖规则（必须一致）

- 对同一条边，新任务写回必须覆盖旧的 `analysis.*` 字段；
- 覆盖以 `analysis.task_id` 为准：写回时先清空旧的 `analysis.*` 字段，再写入新值；
- 前端查询溯源结果时，只展示 `analysis.task_id` 等于当前任务 ID 的结果。
