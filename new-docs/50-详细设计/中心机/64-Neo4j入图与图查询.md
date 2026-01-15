# Neo4j入图与图查询

## 文档目的

本文件从中心机实现角度描述 Neo4j 的入图边界、写入规则与图查询能力。

## 读者对象

- 负责 Neo4j 入图与查询实现的同学
- 负责前端图可视化与溯源联调的同学

## 引用关系

- ECS 字段规范（权威口径）：`../../80-规范/81-ECS字段规范.md`
- 图谱规范（权威口径）：`../../80-规范/84-Neo4j实体图谱规范.md`
- 溯源写回规范（权威口径）：`../../80-规范/85-溯源结果写回规范.md`
- 图谱回标与边属性（详细设计）：`65-图谱回标与边属性.md`

## 1. 模块职责与边界

Neo4j 模块负责“实体关系图（Entity Graph）”的权威存储与图查询能力，具体职责固定为：

1. **Schema 管理**：创建并维持节点唯一约束与常用索引；
2. **入图写入**：将输入的 ECS 文档转换为节点/边，并写入 Neo4j；
3. **时间窗查询**：支持按时间窗查询边集合（供图可视化与算法使用）；
4. **图算法查询**：支持基于时间窗投影图的最短路（Neo4j GDS）；
5. **结果承载**：承载溯源任务写回的边属性，供后续“按节点查询溯源结果”。

本模块不负责：

- OpenSearch 的检测与融合（见 `63-检测与告警融合.md`）；
- 溯源算法的具体执行（见 `../../50-详细设计/分析/`）；
- ECS 字段口径（见 `../../80-规范/81-ECS字段规范.md`）。

## 2. Schema 与约束

### 2.1 节点唯一约束（必须存在）

节点类型与唯一键由 `../../80-规范/84-Neo4j实体图谱规范.md` 定义。Neo4j 必须落地以下唯一约束（表达为“Label + 属性键”）：

| Label | 唯一键 |
|---|---|
| `Host` | `host.id` |
| `User` | `user.id` |
| `User` | `host.id + user.name` |
| `Process` | `process.entity_id` |
| `File` | `host.id + file.path` |
| `Domain` | `domain.name` |
| `IP` | `ip` |

> 说明：`User` 与 `File` 的复合键用于避免跨主机误合并；当事件包含 `user.id` 时使用 `user.id` 作为唯一键；当事件不包含 `user.id` 时使用 `host.id + user.name` 作为唯一键。

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

每条入图边必须写入以下属性（字段名与来源以 `../../80-规范/81-ECS字段规范.md` 与 `../../80-规范/84-Neo4j实体图谱规范.md` 为准）：

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
- `analysis_edges_by_task`

接口的请求/响应字段由后端实现固定，Neo4j 模块负责提供稳定的查询语义与返回结构（nodes/edges 的 uid、rtype、props）。

其中：

- `analysis_edges_by_task`：按 `analysis.task_id` 拉取该任务写回的边集合；当请求参数 `only_path=true` 时只返回 `analysis.is_path_edge=true` 的关键路径边；当 `only_path=false` 时返回该任务写回的全部边。

## 5. 结果写回：边属性规范

溯源结果写回属于“图谱回标与边属性”的详细设计范围：

- 写回数据结构（权威口径）：`../../80-规范/85-溯源结果写回规范.md`
- 工程实现与读取口径：`65-图谱回标与边属性.md`
