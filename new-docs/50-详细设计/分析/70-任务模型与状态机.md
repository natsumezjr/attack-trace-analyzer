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

每个任务在 `analysis-tasks-*` 中保存 1 条任务文档，字段集合固定为（核心字段 + 任务级结构化结果）：

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

此外，任务必须写入以下“任务级结果”字段（用于展示/报告复用）：

- `task.result.ttp_similarity.attack_tactics[]`：本任务时间窗内的 ATT&CK tactic id 集合（TAxxxx）
- `task.result.ttp_similarity.attack_techniques[]`：本任务时间窗内的 ATT&CK technique id 集合（Txxxx[.xxx]）
- `task.result.ttp_similarity.similar_apts[]`：Top-3 相似组织列表（数组，每项包含 intrusion_set / similarity_score / top_tactics / top_techniques）
- `task.result.trace.updated_edges`：写回到 Neo4j 的边数量
- `task.result.trace.path_edges`：其中关键路径边数量（`analysis.is_path_edge=true`）

### 3.3 状态机（必须严格）

状态转移只能是：

- `queued → running`
- `running → succeeded`
- `running → failed`

任何回退、跳转均禁止。

### 3.4 后端对外 API（固定）

Analysis 模块的异步任务由后端 API 对外暴露，接口形状固定为：

- `POST /api/v1/analysis/tasks`：创建任务（返回 `task_id`，并入队异步执行）
- `GET /api/v1/analysis/tasks/{task_id}`：查询任务状态/进度/任务级结果（OpenSearch 任务文档）
- `GET /api/v1/analysis/tasks`：按条件列出任务（用于前端任务列表/调试）

任务执行完成后的图结果读取有两种方式：

1) 继续使用 `POST /api/v1/graph/query` 的 `edges_in_window` 拉边，并在前端筛选 `analysis.task_id == task_id`；或
2) 使用 `POST /api/v1/graph/query` 的 `analysis_edges_by_task` 动作，直接按 `task_id` 拉取本次写回边（可选 `only_path=true`）。

## 4. 算法流水线（固定阶段）

### 4.1 输入

输入由 Neo4j 提供：

- 在 `[start_ts, end_ts]` 时间窗内与目标节点相关的边集合；
- 边必须包含：`ts_float`、`is_alarm`、`threat.*`、`custom.evidence.event_ids` 等字段（字段存在性要求见 `32` 与 `52`）。

### 4.2 处理阶段

本任务在同一个 `task_id` 下必须执行 **两条主算法 + 一条派生标注**，三者都必须完成（没有可选开关），并且都要产出可回溯的结构化输出：

1. **主算法-Trace（回溯链条/关键路径）**：从 Neo4j 读取目标节点相关子图，生成“关键边集合 + 子图边集合 + 风险/解释”，并写回 Neo4j 的 `analysis.*` 字段。
2. **主算法-TTP Similarity（APT 组织匹配）**：从 OpenSearch 的 Canonical Findings 提取 `threat.tactic.id + threat.technique.id`，结合离线 Enterprise CTI 计算 Top-3 相似组织，写入 OpenSearch 的任务文档 `task.result.ttp_similarity.*`。
3. **派生标注（Edge-level TTP）**：对 Trace 的关键路径边，派生并写回 `analysis.ttp.technique_ids[]`（从边的 `threat.technique.*` 字段提取/展开），用于前端高亮与报告解释。

其中 Trace 的算法流水线仍按 Phase A/B/C/D 描述（细节见下文），但它必须与 TTP Similarity 同一任务内共同执行与落库。

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

#### Phase C：LLM 路径选择（实际实现）

- 输入：Phase B 的语义候选子图（包含多个锚点对的候选路径）
- 处理：
  - 构建 LLM payload：包含段摘要（段内异常边摘要）和每对锚点的候选路径集合
  - Payload 裁剪：对字段进行白名单过滤和长度截断，控制 token 数量
  - 启发式预筛选（可选）：基于 hop 长度和实体一致性对候选路径排序，保留 top-K
  - LLM 选择：调用 LLM 在全链一致性视角下，为每个锚点对选择一条最可能的路径
  - 输出验证：校验 LLM 返回的 path_id 是否有效，失败则回退到最短 hop 策略
- 输出：选中的路径集合（KillChain），包含全链解释文本

#### Phase D/E：特征提取与 TTP 比对（当前留白）

- Phase D：从最终 killchain 提取 TTP 特征向量（待实现）
- Phase E：与现有 TTP 特征库比对（待实现）

### 4.3 算法详细说明

#### 4.3.1 Phase A：攻击阶段骨架（Attack FSA）

**核心思想**：将异常边序列映射为 MITRE ATT&CK 战术状态序列，通过有限状态自动机（FSA）筛选出符合攻击链逻辑的骨架序列。

**算法流程**：

1. **输入预处理**：
   - 获取时间窗内所有 `is_alarm=true` 的异常边
   - 按时间戳升序排序，保证处理顺序符合事件时间线

2. **状态映射**：
   - 从边的 `threat.tactic.name` 字段（或通过 `get_attack_tag()` 方法）提取攻击标签
   - 将标签映射到 14 个 ATT&CK 战术状态之一：
     - Reconnaissance（侦察）
     - Resource Development（资源开发）
     - Initial Access（初始访问）
     - Execution（执行）
     - Persistence（持久化）
     - Privilege Escalation（权限提升）
     - Defense Evasion（防御规避）
     - Credential Access（凭据访问）
     - Discovery（发现）
     - Lateral Movement（横向移动）
     - Collection（收集）
     - Command and Control（命令与控制）
     - Exfiltration（数据渗出）
     - Impact（影响）

3. **状态转移规则**：
   - 定义 `TransitionPolicy`，指定每个状态允许的后继状态集合
   - 允许自环（同一阶段多条告警）
   - 允许从任意状态开始（`allow_start_anywhere=True`）
   - 支持显式跳转对（`allow_jump_pairs`）

4. **Beam Search 与分支策略**：
   - 维护多个假设（Hypothesis），每个假设代表一条可能的状态序列
   - 对每条异常边，尝试将其加入当前假设：
     - **DIRECT 分支**：如果状态转移合法，直接扩展假设
     - **POP 分支**：如果转移不合法，回溯 pop 若干关键边，直到可以接入
     - **DROP 分支**：丢弃该边，认为可能是噪声
   - 使用去重机制：相同位置、相同末状态、相同末锚点的假设视为等价，只保留评分最高的
   - Beam 截断：每轮只保留评分最高的 `beam_width` 个假设（默认 30）

5. **评分机制**：
   - `score_hint = key_edge_count - 0.25 * drops - 0.5 * pops`
   - 关键边越多越好，DROP/POP 操作会扣分

6. **接受态与输出**：
   - 当假设到达接受态（默认：Exfiltration、Impact、Command and Control）时，输出一条 FSAGraph
   - FSAGraph 包含：关键边节点序列（`is_key=True`）、状态段划分、决策 trace
   - 输出后清空假设，继续寻找下一条链

**关键参数**：
- `max_backtrack_edges`：POP 分支最多回溯的边数（默认 10）
- `beam_width`：同时保留的假设数上限（默认 30）
- `accept_states`：接受态集合（默认包含 Exfiltration、Impact、Command and Control）

#### 4.3.2 Phase B：子图补全（Graph Completion）

**核心思想**：在 Phase A 产生的关键边序列的相邻段锚点之间，枚举候选连接路径，将骨架补全为弱连通子图。

**算法流程**：

1. **段划分**：
   - 将 FSAGraph 的关键边按状态聚合成连续段（StateSegment）
   - 每段提供：状态、时间窗口 `[t_start, t_end]`、进入锚点 `anchor_in_uid`、退出锚点 `anchor_out_uid`

2. **锚点对候选路径枚举**：
   对每个相邻段对 `(seg_i, seg_{i+1})`：
   - 确定时间窗口：`[seg_i.t_end - margin, seg_{i+1}.t_start + margin]`（margin 用于抗时钟偏差，默认 1.0 秒）
   - 确定最大 hop 数：根据段状态动态设置（Reconnaissance/Discovery/Lateral Movement 允许 10 hop，Command and Control 允许 6 hop，其他默认 8 hop）
   - 查询边池：从 Neo4j 获取时间窗内的边，过滤关系类型白名单（SPAWN、LOGON、RUNS_ON、FILE_ACCESS、NET_CONNECT、DNS_QUERY、RESOLVES_TO、HAS_IP）
   - 路径枚举：
     - 优先尝试使用 Neo4j API 的路径查询接口（如果返回路径集合，直接使用）
     - 否则使用本地 BFS 枚举：
       - 构建无向邻接表（支持双向遍历，提高鲁棒性）
       - BFS 搜索从 `anchor_out_uid` 到 `anchor_in_uid` 的路径
       - 限制 hop 数、路径时间单调性（允许 `TIME_SKEW_TOLERANCE_SEC` 容忍）
       - 限制路径数量（第一轮 `FIRST_K=10`，第二轮 `SECOND_K=25`）

3. **多级枚举策略**：
   - Stage 1：使用标准 `max_hops` 和 `FIRST_K` 限制枚举
   - Stage 2：如果 Stage 1 无结果，放宽到 `max_hops+2` 和 `SECOND_K` 限制
   - 最终每个锚点对最多保留 `MAX_PATHS_PER_PAIR=20` 条候选路径

4. **缓存机制**：
   - 使用 `AnchorPairCache` 缓存锚点对的候选路径
   - 缓存 key：`(src_anchor, dst_anchor, t_min_rounded, t_max_rounded, constraints_sig)`
   - 使用 FIFO 淘汰策略，最大条目数 `MAX_CACHE_ITEMS=300`

5. **段内摘要构建**：
   - 对每段内的异常边，选取 top-N（默认 6）条信息量较高的边
   - 构建边摘要：包含 edge_id、时间戳、src/dst、关系类型、关键 ECS 字段（白名单过滤、长度截断）

6. **输出**：
   - 如果任意相邻锚点对无候选路径，丢弃该 FSAGraph
   - 否则输出 `SemanticCandidateSubgraph`，包含：FSAGraph、段摘要列表、锚点对候选路径列表

**关键参数**：
- `TIME_MARGIN_SEC`：锚点窗口扩展 margin（默认 1.0 秒）
- `TIME_SKEW_TOLERANCE_SEC`：路径内时间单调约束容忍（默认 0.0 秒）
- `FIRST_K`：第一轮最多保留的候选路径数（默认 10）
- `SECOND_K`：第二轮最多保留的候选路径数（默认 25）
- `MAX_PATHS_PER_PAIR`：每对锚点最终给 LLM 的候选路径数上限（默认 20）

#### 4.3.3 Phase C：LLM 路径选择

**核心思想**：使用 LLM 在全链一致性视角下，为每个锚点对选择一条最可能的连接路径，并生成解释文本。

**算法流程**：

1. **Payload 构建**：
   - 输入：`SemanticCandidateSubgraph`
   - 构建结构：
     - `segments`：段摘要列表（包含段状态、时间窗口、锚点、段内异常边摘要）
     - `pairs`：锚点对列表，每个 pair 包含候选路径集合
     - 每个候选路径包含：`path_id`、`steps`（路径步骤摘要）

2. **Payload 裁剪（PayloadReducer）**：
   - 字段白名单过滤：只保留关键解释字段（edge_id、时间戳、关系类型、威胁信息、实体信息等）
   - 长度截断：字符串字段超过 `max_str_len`（默认 200）时截断
   - 步数限制：每条候选路径最多保留 `max_steps_per_path`（默认 10）步

3. **启发式预筛选（HeuristicPreselector，可选）**：
   - 对每个锚点对的候选路径评分：
     - 基础分：`10.0 / (1.0 + hop)`（hop 越短越好）
     - 一致性加分：与全局上下文 token（process.entity_id、host.id、user.name 等）的重叠度
   - 按评分排序，每个 pair 只保留 top-K（默认 8）条候选给 LLM
   - 维护全局 token 上下文，鼓励跨 pair 的实体一致性

4. **LLM 调用**：
   - 构建 prompt：
     - System：定义角色（高级事件响应专家）和任务（选择最可能的 killchain 连接路径）
     - User：包含任务描述、输出 schema、输入 payload、选择规则
   - 调用 LLM API（支持 OpenAI 兼容接口）
   - 期望输出 JSON：
     ```json
     {
       "chosen_path_ids": ["p-...", "p-...", ...],
       "explanation": "全局解释文本",
       "pair_explanations": [
         {"pair_idx": 0, "path_id": "p-...", "why": "解释文本"}
       ]
     }
     ```

5. **输出验证与回退**：
   - 验证 `chosen_path_ids` 数量必须等于 pairs 数量
   - 验证每个 `path_id` 必须存在于对应 pair 的候选集合中
   - 如果验证失败或 LLM 调用失败，回退到 fallback 策略：
     - 每个 pair 选择 hop 最短的候选路径
     - 生成占位解释文本

6. **KillChain 物化**：
   - 将选中的 `path_id` 列表映射回 `CandidatePath` 对象
   - 生成 `KillChain` 对象，包含：
     - `kc_uuid`：唯一标识符
     - `fsa_graph`：原始 FSAGraph
     - `segments`：段摘要
     - `selected_paths`：选中的路径集合
     - `explanation`：全链解释文本

**关键参数**：
- `per_pair_keep`：每个 pair 最多保留给 LLM 的候选数（默认 8）
- `max_steps_per_path`：每条候选路径最多步数（默认 10）
- `max_str_len`：文本字段截断长度（默认 200）
- `require_pair_explanations`：是否要求逐 pair 解释（默认 True）

#### 4.3.4 Phase D/E：特征提取与 TTP 比对（当前留白）

- **Phase D**：从最终 killchain 提取 TTP 特征向量（待实现）
- **Phase E**：与现有 TTP 特征库比对（待实现）

#### 4.3.5 结果持久化

**写回逻辑**：

1. **收集边集合**：
   - Phase A 的关键边（FSA key edges）
   - Phase C 选中的连接路径边

2. **写入 killchain uuid**：
   - 对每条边写入 `custom.killchain.uuid = kc_uuid`（ECS 合规字段）
   - 对边涉及的节点 uid，生成最小 GraphNode 并写入 `custom.killchain.uuid`
   - 调用 `graph_api.add_edge` 和 `graph_api.add_node` 写入 Neo4j（假设支持 upsert/merge）

3. **边去重**：使用稳定 edge_id（优先 `event.id`，否则基于 src/dst/rtype/ts 的 hash）去重

### 4.4 解释性摘要（固定输出）

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
