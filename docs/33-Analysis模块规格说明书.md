# Analysis 模块规格说明书

## 1. 模块职责与边界

Analysis 模块负责“老师点选节点 → 系统给出可解释的溯源结果”的完整闭环，职责固定为：

1. **异步任务执行**：接收后端创建的溯源任务，异步执行并持续更新任务进度；
2. **图数据读取**：从 Neo4j 获取目标节点相关的子图数据；
3. **算法流水线**：对异常边序列做攻击阶段组织、图补全与风险路径计算；
4. **解释性输出**：产出用于展示/报告的解释摘要（写回边属性与任务文档）；
5. **结果写回**：把最终结果写回 Neo4j 边属性，并更新 OpenSearch 任务状态。

本模块不负责：

- OpenSearch 的 Store-first 检测与 raw→canonical 融合（见 `31-OpenSearch模块规格说明书.md`）；
- Neo4j 的 schema、基础图查询与最短路接口（见 `32-Neo4j模块规格说明书.md`）。

## 2. 触发方式（固定）

Analysis 模块只通过“前端触发的溯源任务”运行：

1) 前端在图上选择目标节点；
2) 请求后端创建任务；
3) 后端返回 `task_id` 并把任务入队；
4) Analysis 模块执行任务并写回结果。

Analysis 模块不由中心机定时流水线自动触发；定时流水线只负责“入库/检测/融合/入图”。

## 3. 异步任务模型

### 3.1 task_id 生成规则

`task_id` 必须全局唯一，格式固定为：

- `trace-<uuid_v4>`

### 3.2 任务文档存储（OpenSearch）

每个任务在 `analysis-tasks-*` 中保存 1 条任务文档，字段集合固定为：

- `@timestamp`：任务创建时间（RFC3339）
- `task.id`：`task_id`
- `task.status`：`queued` / `running` / `succeeded` / `failed`
- `task.progress`：整数 0–100
- `task.target.node_uid`：目标节点 UID
- `task.window.start_ts`：分析时间窗起点（RFC3339）
- `task.window.end_ts`：分析时间窗终点（RFC3339）
- `task.started_at`：任务开始执行时间（RFC3339）
- `task.finished_at`：任务结束时间（RFC3339）
- `task.error`：失败原因（字符串）
- `task.result.summary`：任务结果摘要（字符串）

### 3.3 状态机（必须严格）

状态转移只能是：

- `queued → running`
- `running → succeeded`
- `running → failed`

任何回退、跳转均禁止。

## 4. 算法流水线（固定阶段）

### 4.1 输入

输入由 Neo4j 提供：

- 在 `[start_ts, end_ts]` 时间窗内与目标节点相关的边集合；
- 边必须包含：`ts_float`、`is_alarm`、`threat.*`、`custom.evidence.event_ids` 等字段（字段存在性要求见 `32` 与 `52`）。

### 4.2 处理阶段

算法流水线固定为四个阶段（Phase A/B/C/D），每个阶段的输出都必须可用于解释与回溯：

#### Phase A：攻击阶段骨架（Attack FSA）

- 输入：异常边集合（`is_alarm=true` 的边）
- 处理：将异常边按 `threat.tactic.name`（或等价字段）映射为 ATT&CK 战术状态，并按状态转移规则筛选出“可接受的攻击骨架序列”。
- 输出：关键边序列（Kill-chain skeleton）

#### Phase B：子图补全（Graph Completion）

- 输入：Phase A 的关键边序列
- 处理：在相邻关键边的锚点之间，从 Neo4j 查询时间窗内的“连接边”，把骨架补成弱连通子图。
- 输出：弱连通子图（关键边 + 补全边）

#### Phase C：风险赋权与解释特征提取

- 输入：Phase B 的子图
- 处理：对每条边计算风险评分，风险评分由“关系类型权重 + 解释性信号”共同决定。
- 输出：带 `analysis.risk_score` 的边集合，以及任务级摘要特征（Technique 集合等）

#### Phase D：关键路径选择

- 输入：Phase C 的子图
- 处理：选择总风险最高的路径或边集合，作为对外展示的“溯源关键路径”。
- 输出：关键路径边集合（用于写回 `analysis.is_path_edge=true`）

### 4.3 解释性摘要（固定输出）

任务完成时必须生成 1 段摘要文本，写入：

- OpenSearch：`task.result.summary`
- Neo4j：每条关键路径边的 `analysis.summary`

摘要文本必须能回答：

- 目标节点在时间窗内的主要异常行为是什么；
- 关键路径由哪些关系类型组成；
- 涉及的 Technique ID 是哪些（来自 Canonical Finding 的 `threat.technique.id`）。

## 5. 结果写回

### 5.1 写回对象

写回对象固定为“时间窗内参与结果的边”，其中：

- 关键路径边必须写入 `analysis.is_path_edge=true`
- 非关键边写入 `analysis.is_path_edge=false` 并清空其它 `analysis.*` 字段

### 5.2 写回字段（与 32 对齐）

写回字段集合与覆盖规则由 `32-Neo4j模块规格说明书.md` 的第 5 章定义；Analysis 模块必须严格遵守。
