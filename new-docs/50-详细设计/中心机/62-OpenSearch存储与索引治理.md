# OpenSearch存储与索引治理

## 文档目的

本文件从中心机实现角度描述 OpenSearch 的存储边界、索引组织、入库路由、字段规范化与去重治理。

## 读者对象

- 负责中心机后端实现的同学
- 负责数据验证与排障的同学

## 引用关系

- ECS 字段规范（权威口径）：`../../80-规范/81-ECS字段规范.md`
- OpenSearch 索引与 mapping 规范（权威口径）：`../../80-规范/82-OpenSearch索引与Mapping规范.md`
- 数据对象与生命周期（权威口径）：`../../80-规范/80-数据对象与生命周期.md`
- 检测与告警融合（详细设计）：`63-检测与告警融合.md`

## 1. 模块职责与边界

OpenSearch 模块负责中心机侧“事实/告警/任务元数据”的权威存储与检索能力，具体职责固定为：

1. **索引体系**：定义索引命名、按日滚动策略、生命周期保留策略；
2. **入库路由**：根据 `event.kind` 与 `event.dataset` 将文档写入正确索引；
3. **字段处理**：对 ECS 文档执行三时间字段处理、扁平键兼容、基础校验；
4. **Store-first 检测**：触发 OpenSearch Security Analytics 扫描 Telemetry 并产出 Findings；
5. **融合去重**：将 Raw Findings 融合为 Canonical Findings 并写回 OpenSearch；
6. **任务存储**：保存溯源任务的状态与元数据，供前端轮询。

本模块不负责：

- Neo4j 图谱建模与查询（见 `64-Neo4j入图与图查询.md` 与 `../../80-规范/84-Neo4j实体图谱规范.md`）；
- 溯源算法与结果写回（见 `../../50-详细设计/分析/` 与 `../../80-规范/85-溯源结果写回规范.md`）；
- 客户机采集与接口（见 `../../50-详细设计/客户机/` 与 `../../80-规范/87-客户机与中心机接口.md`）。

## 2. 索引体系与命名

### 2.1 索引清单（系统运行时必须存在）

| 索引模式 | 数据对象 | 写入方 | 用途 |
|---|---|---|---|
| `ecs-events-YYYY-MM-DD` | Telemetry | 中心机流水线 Step 2 | 事实事件检索、Store-first 检测输入 |
| `raw-findings-YYYY-MM-DD` | Raw Findings | 中心机流水线 Step 3 | 原始告警审计、融合输入 |
| `canonical-findings-YYYY-MM-DD` | Canonical Findings | 中心机流水线 Step 3 | 图谱与溯源的主输入 |
| `client-registry` | 客户机注册表 | 客户机注册 + 流水线更新 | 客户机列表、游标、在线状态 |
| `analysis-tasks-YYYY-MM-DD` | Trace Task | Analysis 模块 | 异步任务状态与进度轮询 |

> 说明：索引保留策略在第 6 节定义；ECS 字段口径在 `../../80-规范/81-ECS字段规范.md` 定义。

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

中心机写入 OpenSearch 前必须保证三时间字段满足 `../../80-规范/81-ECS字段规范.md`：

- `@timestamp`：主时间轴。若缺失，必须从 `event.created` 推导；若仍无法得到，中心机必须丢弃该文档。
- `event.created`：观察时间。若缺失，中心机必须回填为 `@timestamp`。
- `event.ingested`：入库时间。中心机必须覆盖为“当前入库时间”，不得使用上游携带值。

### 3.3 幂等与去重（必须满足）

1. 每条文档必须具备 `event.id`。  
2. 中心机写入必须按 `event.id` 幂等：同一 `event.id` 重复写入不得产生重复文档。  
3. 对于无法保证 `event.id` 稳定的上游输入，必须在进入中心机前补齐稳定 `event.id`。

## 4. 检测与融合

OpenSearch 的检测触发、Raw Finding 生成与 Canonical Finding 融合去重规则在本项目中属于独立的详细设计章节：

- `63-检测与告警融合.md`

## 5. 保留策略与脚本

### 5.1 数据保留周期（固定）

保留周期的权威口径见：`../../80-规范/80-数据对象与生命周期.md`。

### 5.2 初始化与运维脚本（入口）

OpenSearch 侧的初始化动作固定为：

1) 启动 OpenSearch 容器；  
2) 启动中心机后端，后端在启动阶段调用 `initialize_indices()` 创建/确保索引存在（包含 mapping）；  
3) 配置 Security Analytics detector，并导入 Sigma 规则。  

脚本入口固定为以下文件：

- Sigma 规则导入：`backend/app/services/opensearch/scripts/import_sigma_rules.py`
- Security Analytics detector 配置：`backend/app/services/opensearch/scripts/setup_security_analytics.py`
