# ECS 字段规范（ECS 子集 v1）

> **本文定位**：ECS 字段规范（ECS 子集）是项目的**数据归一化标准**，用于约束归一化字段口径与 dataset 约定。
>
> **核心约定**：
> - ECS 版本固定为 **v9.2.0**（统一写 `ecs.version=9.2.0`）
> - 所有自定义字段统一放入 **`custom.*`** 命名空间（避免污染 ECS 标准字段）
> - 标记约定：`✅` = 必填；`⭐` = 建议；`⭕` = 可选
>
> **覆盖范围**：公共字段 + 三类数据源（主机日志/主机行为/网络流量）+ 检测告警（ATT&CK 映射），满足时间对齐、会话重建、关联/溯源的最小字段需求。
>
> **相关文档**：
> - 存储与建模（OpenSearch 索引划分、Neo4j 图模型）：`docs/03B-存储与图谱设计.md`
> - 客户端 ↔ 中心机接口：`docs/03C-客户端中心机接口规范.md`

---

## 目录

- [0. 总体约束（全局口径）](#0-总体约束全局口径)
- [1. 公共字段（所有数据源）](#1-公共字段所有数据源统一要求)
- [2. Telemetry：主机日志（hostlog.*）](#2-telemetry主机日志-host-logs-hostlog)
- [3. Telemetry：主机行为（hostbehavior.*）](#3-telemetry主机行为-host-behavior-hostbehavior)
- [4. Telemetry：网络流量（netflow.*）](#4-telemetry网络流量-net-flow-protocol-netflow)
- [5. Findings/Alerts：检测告警（finding.*）](#5-findingsalerts检测告警-finding--custom)
- [6. JSON 示例（接口对齐与测试）](#6-json-示例用于对齐接口与测试数据)
- [7. 分工交付边界](#7-分工交付边界)
- [8. 附录](#8-可继续补充实现过程中常用)

---

## 0. 总体约束（全局口径）

### 0.1 事件类型（event.kind）

`event.kind` 是**最顶层的分类**，决定事件的路由和处理方式。

| 值 | 说明 | 存储位置 | 示例场景 |
|---|------|---------|---------|
| `event` | 事实事件（Telemetry），不做善恶判断 | `ecs-events-*` | 用户登录、进程启动、DNS 查询 |
| `alert` | 检测告警/发现（Finding），带规则/ATT&CK 标注 | `raw-findings-*` / `canonical-findings-*` | Falco 规则命中、Suricata 告警 |

**约束**：所有事件必须包含 `event.kind` 字段，且值必须为 `event` 或 `alert` 之一。

---

### 0.2 时间字段（三时间）

为满足**时间序列对齐 + 回放 + 排障**，统一采用 3 个时间字段：

| 字段 | 类型 | 说明 | 用途 | 示例 |
|------|------|------|------|------|
| `@timestamp` | `date` | 对齐后的事件发生时间 | 排序、时间窗关联的主时间轴 | `2026-01-12T03:21:10.123Z` |
| `event.created` | `date` | 采集器/传感器观察到事件的时间 | 衡量端侧延迟（`event.created - @timestamp`） | `2026-01-12T03:21:12.001Z` |
| `event.ingested` | `date` | 中心侧入库时间 | 衡量链路/管道延迟（`event.ingested - event.created`） | `2026-01-12T03:21:12.900Z` |

**约束**：
- 所有事件**必须包含**三个时间字段
- `@timestamp` 是**排序和时间窗关联的主时间轴**，必须准确对齐
- 允许 `event.created` 与 `@timestamp` 相同（例如源数据只有一个时间戳时）
- 时间格式统一为 ISO 8601（UTC 时区）

---

### 0.3 标识字段（ID 生成策略）

为确保**跨源关联可落地**，约定以下 ID 生成策略：

#### event.id（事件唯一标识）

**用途**：每条入库文档的唯一标识（Telemetry 和 Finding 都必须有），用于：
- 去重与幂等性：防止重复入库
- 证据关联：告警通过 `custom.evidence.event_ids` 引用原始事件
- 跨索引关联：在 OpenSearch 中作为文档主键

**生成策略**：
- 推荐 1：`uuidv4()`（标准 UUID v4）
- 推荐 2：`sha1(source + raw_unique_key + @timestamp)`（只要稳定且不撞即可）
- 约束：全局唯一，长度不超过 64 字符

**示例**：`evt-1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e`

#### host.id（主机唯一标识）

**用途**：跨源"最强关联键"，用于将主机日志、主机行为、网络流量关联到同一主机。

**生成策略**：
- 优先：使用环境提供的稳定主机 UUID（如云厂商的 instance-id）
- 备选：`sha1(host.name)`（注意：更换主机名会导致漂移）

**约束**：同一主机在不同数据源中 `host.id` 必须一致。

**示例**：`h-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`

#### process.entity_id（进程实例标识）

**用途**：同一主机内对"同一进程实例"的稳定标识，用于串进程树/行为链。

**生成策略**：
- 推荐：`sha1(host.id + pid + process.start_time + process.executable)`
- 备选：使用传感器自带的 entity_id（如 Falco 的 `proc.id`）

**约束**：
- 同一主机内，同一进程实例的所有行为事件必须使用相同的 `process.entity_id`
- 进程重启后必须生成新的 `process.entity_id`

**示例**：`p-f1e2d3c4b5a6978869504132a7b6c8d9`

#### session.id（会话标识）

**用途**：认证会话标识，用于登录会话重建（追踪用户从登录到注销的完整时间线）。

**生成策略**：
- 推荐：`sha1(host.id + user.name + source.ip + floor(@timestamp / Δt))`
- Δt 可取 5–10 分钟，保证同一会话内的所有事件使用相同的 `session.id`

**约束**：
- 同一用户从同一 IP 登录的会话应使用相同的 `session.id`
- 注销事件应与登录事件使用相同的 `session.id`

**示例**：`sess-0123456789abcdef0123456789abcdef`

---

### 0.4 命名空间约定

| 命名空间 | 说明 | 示例 |
|---------|------|------|
| ECS 标准字段 | 遵循 ECS v9.2.0 规范 | `event.*`, `host.*`, `process.*`, `user.*` |
| `custom.*` | 自定义字段，避免污染 ECS | `custom.finding.stage`, `custom.dns.entropy` |

**约束**：所有自定义字段必须使用 `custom.*` 命名空间，不得直接添加 ECS 未定义的字段。

---

## 1. 公共字段（所有数据源统一要求）

### 1.1 必填字段（所有事件）

> **说明**：这里的"必填"指入库前必须补全；若上游没有对应信息，应通过推导/默认值补齐（例如生成 `event.id`、推导 `host.id`）。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `ecs.version` | `keyword` | ✅ | ECS 版本，固定为 `9.2.0` | `9.2.0` |
| `@timestamp` | `date` | ✅ | 对齐后的发生时间（主时间轴） | `2026-01-12T03:21:10.123Z` |
| `event.created` | `date` | ✅ | 采集器看到事件时间 | `2026-01-12T03:21:12.001Z` |
| `event.ingested` | `date` | ✅ | 入库时间 | `2026-01-12T03:21:12.900Z` |
| `event.id` | `keyword` | ✅ | 事件唯一 ID（Telemetry/Finding 都必须有） | `evt-1b2c3d4e5f6a7b8c` |
| `event.kind` | `keyword` | ✅ | `event`（事实事件）或 `alert`（告警） | `event` / `alert` |
| `event.category` | `keyword[]` | ✅ | ECS 事件大类（可多值） | `["authentication"]`, `["process", "file"]` |
| `event.type` | `keyword[]` | ✅ | ECS 事件类型（可多值） | `["start"]`, `["creation", "change"]` |
| `event.action` | `keyword` | ✅ | 动作枚举（用于检索/规则） | `user_login`, `file_create` |
| `event.dataset` | `keyword` | ✅ | 数据集名称 | `hostlog.auth`, `netflow.dns` |
| `host.id` | `keyword` | ✅ | 主机唯一标识（见 0.3） | `h-a1b2c3d4e5f6a7b8c` |
| `host.name` | `keyword` | ✅ | 主机名（演示/检索更友好） | `victim-01`, `sensor-01` |
| `agent.name` | `keyword` | ✅ | 采集器名称 | `wazuh-agent`, `suricata` |
| `agent.version` | `keyword` | ✅ | 采集器版本 | `4.0.0`, `7.0.0` |

**约束**：
- `ecs.version` 必须为 `9.2.0`
- `event.kind` 必须为 `event` 或 `alert`
- `event.dataset` 必须遵循命名约定：`hostlog.*`, `hostbehavior.*`, `netflow.*`, `finding.*`

---

### 1.2 强烈建议字段（强关联 / 回放 / 排障）

| 字段 | 类型 | 建议 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.original` | `text` | ⭐ | 原始日志/原始 JSON（证据回放、截图） | `Jan 12 03:21:10 sshd[1234]: ...` |
| `event.code` | `keyword` | ⭐ | EventID / syscall / 协议码等 | `4624`, `execve`, `2` |
| `event.outcome` | `keyword` | ⭐ | `success` 或 `failure`（认证/访问控制类必填） | `success`, `failure` |
| `message` | `text` | ⭐ | 人类可读摘要 | `User alice logged in from 10.0.0.8` |
| `process.entity_id` | `keyword` | ⭐ | 进程实例标识（存在进程语义的事件必填） | `p-f1e2d3c4b5a69788` |
| `user.name` | `keyword` | ⭐ | 账号（存在认证/进程语义的事件必填） | `alice`, `root` |
| `related.user` | `keyword[]` | ⭐ | 聚合检索用：关联用户集合 | `["alice", "bob"]` |
| `related.ip` | `ip[]` | ⭐ | 聚合检索用：关联 IP 集合 | `["10.0.0.5", "10.0.0.8"]` |

**使用场景**：
- `event.original`：用于证据回放、截图、审计
- `event.code`：用于快速定位原始事件类型（如 Windows EventID）
- `event.outcome`：用于成功/失败统计和关联分析
- `related.*`：用于跨索引聚合检索（如查找所有与某用户相关的事件）

---

## 2. Telemetry：主机日志（Host Logs，`hostlog.*`）

> **数据源**：Wazuh（本项目主机日志采集只使用 Wazuh）。
>
> **说明**：Wazuh 侧输出的事件/告警需在归一化层映射为 ECS 子集字段（本文口径），再进入 OpenSearch 与后续关联/串链。
>
> **Dataset 划分**：
> - `hostlog.auth`：认证/登录（用于会话重建、横向移动）
> - `hostlog.process`：进程事件（用于进程树与执行链）
> - `hostlog.file_registry`：文件/注册表（用于敏感访问与持久化痕迹）

---

### 2.1 `hostlog.auth`（认证/登录）

**用途**：记录用户登录/注销事件，用于会话重建、横向移动检测。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostlog.auth` | `hostlog.auth` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `authentication` | `["authentication"]` |
| `event.type` | `keyword[]` | ✅ | 登录用 `start`，注销用 `end`，失败用 `info` | `["start"]`, `["end"]`, `["info"]` |
| `event.action` | `keyword` | ✅ | 动作类型 | `user_login` / `user_logout` / `logon_failed` |
| `event.outcome` | `keyword` | ✅ | 成功或失败 | `success`, `failure` |
| `user.name` | `keyword` | ✅ | 用户名/账号 | `alice`, `root` |
| `source.ip` | `ip` | ✅ | 登录源 IP | `10.0.0.8` |
| `session.id` | `keyword` | ✅ | 会话 ID（见 0.3） | `sess-0123456789abcdef` |
| `authentication.method` | `keyword` | ⭐ | 认证方式 | `password`, `ssh_key`, `kerberos` |
| `event.code` | `keyword` | ⭐ | Windows EventID / Linux auth code | `4624` (Windows), `PAM:authentication` (Linux) |

**约束**：
- 登录事件（`event.type = start`）和注销事件（`event.type = end`）必须使用相同的 `session.id`
- 失败的登录尝试（`event.outcome = failure`）可以不包含 `session.id`（因为未建立会话）

**关联分析**：
- 基于 `session.id` 重建会话时间线（登录 → 活动 → 注销）
- 基于 `user.name` + `source.ip` 检测异常登录（如异地登录）

---

### 2.2 `hostlog.process`（进程事件）

**用途**：记录进程启动/终止事件，用于进程树与执行链分析。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostlog.process` | `hostlog.process` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `process` | `["process"]` |
| `event.type` | `keyword[]` | ✅ | 进程启动用 `start`，终止用 `end` | `["start"]`, `["end"]` |
| `event.action` | `keyword` | ✅ | 动作类型 | `process_start`, `process_end` |
| `process.pid` | `long` | ✅ | PID | `1234` |
| `process.executable` | `keyword` | ✅ | 可执行文件路径（绝对路径） | `/usr/bin/ssh`, `C:\Windows\System32\cmd.exe` |
| `process.command_line` | `wildcard` | ⭐ | 命令行（完整参数） | `ssh user@10.0.0.8`, `cmd.exe /c whoami` |
| `process.parent.pid` | `long` | ⭐ | 父进程 PID（PPID） | `456` |
| `process.parent.entity_id` | `keyword` | ⭐ | 父进程 entity_id（用于树分析） | `p-f1e2d3c4b5a69788` |
| `process.parent.executable` | `keyword` | ⭐ | 父进程可执行文件 | `C:\Windows\explorer.exe` |
| `process.hash.sha256` | `keyword` | ⭐ | 可执行文件 SHA256 哈希 | `a1b2c3d4e5f6...` |
| `process.entity_id` | `keyword` | ⭐ | 进程实例标识（强烈建议补齐） | `p-f1e2d3c4b5a69788` |

**约束**：
- `process.executable` 必须使用绝对路径
- `process.entity_id` 必须与 0.3 节的生成策略一致
- 父子进程关系通过 `process.parent.entity_id` 关联

**关联分析**：
- 基于 `process.entity_id` + `process.parent.entity_id` 构建进程树
- 基于 `process.executable` + `process.command_line` 检测可疑进程（如反向 shell）

---

### 2.3 `hostlog.file_registry`（文件/注册表）

#### 2.3.1 文件操作（`event.category` 包含 `file`）

**用途**：记录文件创建/删除/修改/访问事件，用于敏感访问检测与持久化痕迹分析。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.category` | `keyword[]` | ✅ | 建议包含 `file` | `["file"]` |
| `event.type` | `keyword[]` | ✅ | 操作类型 | `["creation"]`, `["deletion"]`, `["change"]`, `["access"]` |
| `event.action` | `keyword` | ✅ | 动作类型 | `file_create`, `file_delete`, `file_read`, `file_write` |
| `file.path` | `keyword` | ✅ | 文件路径（绝对路径） | `/etc/passwd`, `C:\Windows\System32\config\SAM` |
| `file.name` | `keyword` | ⭐ | 文件名（从路径提取） | `passwd`, `SAM` |
| `process.entity_id` | `keyword` | ⭐ | 进程实例标识（可将文件操作挂到进程） | `p-f1e2d3c4b5a69788` |
| `user.name` | `keyword` | ⭐ | 操作用户 | `root`, `SYSTEM` |

**约束**：
- `file.path` 必须使用绝对路径
- 敏感文件（如 `/etc/passwd`, `C:\Windows\System32\config\SAM`）的操作建议填 `process.entity_id`

**关联分析**：
- 基于 `file.path` 检测敏感文件访问（如密码文件、配置文件）
- 基于 `process.entity_id` 追踪哪个进程进行了文件操作

---

#### 2.3.2 注册表操作（Windows，`event.category` 包含 `registry`）

**用途**：记录 Windows 注册表修改事件，用于持久化痕迹检测（如启动项、计划任务）。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.category` | `keyword[]` | ✅ | 建议包含 `registry` | `["registry"]` |
| `event.type` | `keyword[]` | ✅ | 操作类型（通常为 `change`） | `["change"]` |
| `event.action` | `keyword` | ✅ | 动作类型 | `registry_set_value`, `registry_delete_value` |
| `registry.path` | `keyword` | ✅ | 注册表路径 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| `registry.value` | `keyword` | ⭐ | 键名 | `evil.exe`, `backdoor` |
| `registry.data.strings` | `keyword[]` | ⭕ | 值内容（可选） | `["C:\Temp\evil.exe"]` |

**约束**：
- `registry.path` 使用简短注册表根键（`HKCU`, `HKLM`, ...）
- 持久化相关路径（如 `Run`, `RunOnce`）建议填 `process.entity_id`

**关联分析**：
- 基于 `registry.path` 检测持久化机制（启动项、服务、计划任务）
- 基于 `process.entity_id` 追踪哪个进程修改了注册表

---

## 3. Telemetry：主机行为（Host Behavior，`hostbehavior.*`）

> **数据源**：Falco（本项目主机行为监控只使用 Falco）。
>
> **落地建议**：课程项目不做全量 syscall 入库，优先上报 **Falco 规则命中事件（alert）** 作为主机行为信号；字段仍按本节口径映射到 ECS 子集。
>
> **Dataset 划分**：
> - `hostbehavior.syscall`：系统调用级行为（慎做全量，可只保留高价值）
> - `hostbehavior.file`：文件访问（可从 syscall/传感器提取）
> - `hostbehavior.memory`：内存注入/反射加载（偏告警/特征）

---

### 3.1 `hostbehavior.syscall`（syscall 模板）

**用途**：记录系统调用级行为（如 `execve`, `open`, `connect`），用于进程树与行为链分析。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostbehavior.syscall` | `hostbehavior.syscall` |
| `event.action` | `keyword` | ✅ | syscall 动作类型 | `syscall_execve`, `syscall_open`, `syscall_connect` |
| `event.code` | `keyword` | ✅ | syscall 名/号 | `execve`, `2` |
| `process.entity_id` | `keyword` | ✅ | 进程实例标识（串进程树/行为链的根） | `p-f1e2d3c4b5a69788` |
| `process.pid` | `long` | ✅ | PID | `4321` |
| `process.executable` | `keyword` | ✅ | 可执行文件路径 | `/usr/bin/curl` |
| `process.parent.entity_id` | `keyword` | ⭐ | 父进程 entity_id（进程树分析必需） | `p-a1b2c3d4e5f6a7b8` |
| `user.name` | `keyword` | ⭐ | 执行用户 | `alice` |

**约束**：
- `process.entity_id` 必须可用，用于串进程树/行为链
- `process.parent.entity_id` 强烈建议补齐，用于进程树分析

**关联分析**：
- 基于 `process.entity_id` + `process.parent.entity_id` 构建完整的进程树
- 基于 `event.action` 检测可疑行为链（如 `execve` → `connect` → `write`）

---

### 3.2 `hostbehavior.file`（文件操作）

**用途**：记录文件访问行为（从 syscall 或内核监控提取），用于敏感文件访问检测。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostbehavior.file` | `hostbehavior.file` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `file` | `["file"]` |
| `event.type` | `keyword[]` | ✅ | 操作类型 | `["access"]`, `["change"]`, `["creation"]`, `["deletion"]` |
| `event.action` | `keyword` | ✅ | 动作类型 | `file_read`, `file_write` |
| `file.path` | `keyword` | ✅ | 文件路径（绝对路径） | `/home/alice/.ssh/id_rsa` |
| `process.entity_id` | `keyword` | ✅ | 进程实例标识 | `p-f1e2d3c4b5a69788` |
| `user.name` | `keyword` | ⭐ | 操作用户 | `alice` |

**约束**：
- `file.path` 必须使用绝对路径
- `process.entity_id` 必须可用，用于将文件操作挂到进程

**关联分析**：
- 基于 `file.path` 检测敏感文件访问（如 SSH 密钥、密码文件）
- 基于 `process.entity_id` 追踪哪个进程访问了敏感文件

---

### 3.3 `hostbehavior.memory`（注入/反射加载）

**用途**：记录内存注入/反射加载事件，用于检测进程注入、代码注入等恶意行为。

**说明**：ECS 标准里没有"完美字段组"，本项目采用 **ECS + `custom.*` 特征字段**统一规范。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostbehavior.memory` | `hostbehavior.memory` |
| `event.category` | `keyword[]` | ✅ | 建议为 `process` 或 `malware` | `["process"]`, `["malware"]` |
| `event.type` | `keyword[]` | ✅ | 操作类型 | `["change"]`, `["info"]` |
| `event.action` | `keyword` | ✅ | 动作类型 | `process_injection`, `reflective_load` |
| `process.entity_id` | `keyword` | ✅ | 发起进程（注入源） | `p-src-f1e2d3c4b5a6` |
| `custom.target.process.entity_id` | `keyword` | ⭐ | 被注入进程（注入目标） | `p-dst-a1b2c3d4e5f6` |
| `dll.path` | `keyword` | ⭕ | DLL 注入场景可填（可选） | `C:\Temp\evil.dll` |
| `custom.memory.region_start` | `long` | ⭐ | 注入内存起始地址 | `140737488347136` |
| `custom.memory.region_size` | `long` | ⭐ | 注入内存大小（字节） | `4096` |
| `custom.memory.protection` | `keyword` | ⭐ | 内存保护属性 | `RWX`, `RX` |

**约束**：
- `process.entity_id` 必须指向发起进程（注入源）
- `custom.target.process.entity_id` 建议填被注入进程（注入目标）
- `custom.memory.protection` 建议使用标准缩写（`R`=读, `W`=写, `X`=执行）

**关联分析**：
- 基于 `process.entity_id` + `custom.target.process.entity_id` 检测进程注入关系
- 基于 `custom.memory.protection` 检测 RWX 内存（可疑）

---

## 4. Telemetry：网络流量（Net Flow / Protocol，`netflow.*`）

> **数据源**：Suricata（本项目网络流量采集只使用 Suricata EVE JSON）。
>
> **Dataset 划分**：
> - `netflow.flow`：五元组/会话 + 统计
> - `netflow.dns`：DNS 查询（可加 DNS 隧道特征）
> - `netflow.http`：HTTP 请求（可加隐蔽信道特征）
> - `netflow.icmp`：ICMP（可加隧道特征）

---

### 4.1 `netflow.flow`（Flow/会话）

**用途**：记录网络会话（五元组）与统计信息，用于会话重建与流量分析。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.flow` | `netflow.flow` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `network` | `["network"]` |
| `event.type` | `keyword[]` | ✅ | 会话开始/结束/连接 | `["start"]`, `["end"]`, `["connection"]` |
| `event.action` | `keyword` | ✅ | 动作类型 | `flow_start`, `flow_end` |
| `network.transport` | `keyword` | ✅ | 传输层协议 | `tcp`, `udp`, `icmp` |
| `network.protocol` | `keyword` | ✅ | 应用层协议 | `dns`, `http`, `tls` |
| `source.ip` | `ip` | ✅ | 源 IP | `10.0.0.5` |
| `source.port` | `long` | ✅ | 源端口 | `51514` |
| `destination.ip` | `ip` | ✅ | 目的 IP | `8.8.8.8` |
| `destination.port` | `long` | ✅ | 目的端口 | `53` |
| `flow.id` | `keyword` | ✅ | 流/会话 ID（唯一） | `flow-0123456789abcdef` |
| `network.community_id` | `keyword` | ⭐ | community ID（Suricata 字段） | `1:...` |
| `network.bytes` | `long` | ⭐ | 总字节数（双向） | `12345` |
| `network.packets` | `long` | ⭐ | 总包数（双向） | `120` |

**约束**：
- `flow.id` 必须唯一（同一五元组 + 时间窗的唯一标识）
- 五元组（`source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport`）必填

**关联分析**：
- 基于 `flow.id` 重建完整会话（开始 → 数据传输 → 结束）
- 基于 `network.community_id` 聚合同一会话的所有事件

---

### 4.2 `netflow.dns`（DNS）

**用途**：记录 DNS 查询与响应，用于 DNS 隧道检测与 C2 通信检测。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.dns` | `netflow.dns` |
| `network.protocol` | `keyword` | ✅ | 固定为 `dns` | `dns` |
| `dns.question.name` | `keyword` | ✅ | 查询域名 | `abc.def.example.com` |
| `dns.question.type` | `keyword` | ✅ | 记录类型 | `A`, `AAAA`, `TXT`, `CNAME` |
| `dns.response_code` | `keyword` | ⭐ | 响应代码 | `NOERROR`, `NXDOMAIN` |
| `event.action` | `keyword` | ✅ | 动作类型 | `dns_query`, `dns_tunnel_suspected` |
| `custom.dns.entropy` | `float` | ⭕ | 熵值（DNS 隧道特征） | `4.2` |
| `custom.dns.query_length` | `long` | ⭕ | 查询长度（DNS 隧道特征） | `180` |
| `custom.dns.tunnel_score` | `float` | ⭕ | 隧道评分（0-1） | `0.91` |

**约束**：
- `dns.question.name` 必须为 FQDN（完整域名）
- `dns.question.type` 必须为标准 DNS 记录类型

**关联分析**：
- 基于 `dns.question.name` 检测 DGA（域名生成算法）
- 基于 `custom.dns.entropy` + `custom.dns.query_length` 检测 DNS 隧道

---

### 4.3 `netflow.http`（HTTP）

**用途**：记录 HTTP 请求与响应，用于隐蔽信道检测与 Web 流量分析。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.http` | `netflow.http` |
| `network.protocol` | `keyword` | ✅ | 固定为 `http` | `http` |
| `http.request.method` | `keyword` | ✅ | HTTP 方法 | `GET`, `POST`, `PUT` |
| `url.full` | `wildcard` | ✅ | 完整 URL | `http://example.com/path?query=value` |
| `url.domain` | `keyword` | ⭐ | 域名 | `example.com` |
| `http.response.status_code` | `long` | ⭐ | HTTP 状态码 | `200`, `404`, `500` |
| `user_agent.original` | `text` | ⭕ | User-Agent（可选） | `curl/7.88.1` |
| `event.action` | `keyword` | ✅ | 动作类型 | `http_request`, `http_covert_channel_suspected` |

**约束**：
- `url.full` 必须包含完整的 URL（协议 + 域名 + 路径 + 查询参数）
- `http.request.method` 必须为标准 HTTP 方法

**关联分析**：
- 基于 `url.domain` 检测恶意域名
- 基于 `url.full` 检测隐蔽信道（如大数据量的 POST 请求）

---

### 4.4 `netflow.icmp`（ICMP）

**用途**：记录 ICMP 流量，用于 ICMP 隧道检测与网络探测检测。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.icmp` | `netflow.icmp` |
| `network.transport` | `keyword` | ✅ | 固定为 `icmp` | `icmp` |
| `icmp.type` | `long` | ✅ | ICMP type | `8` (Echo Request), `0` (Echo Reply) |
| `icmp.code` | `long` | ✅ | ICMP code | `0` |
| `event.action` | `keyword` | ✅ | 动作类型 | `icmp_echo`, `icmp_tunnel_suspected` |
| `custom.icmp.payload_size` | `long` | ⭕ | 载荷大小（隧道特征，可选） | `1400` |

**约束**：
- `icmp.type` + `icmp.code` 组合唯一标识 ICMP 消息类型

**关联分析**：
- 基于 `icmp.type` 检测网络探测（如 Ping 扫描）
- 基于 `custom.icmp.payload_size` 检测 ICMP 隧道（异常大的载荷）

---

## 5. Findings/Alerts：检测告警（`finding.*` + `custom.*`）

> **说明**：告警文档同样遵循 ECS 子集（见第 1 节），但必须额外携带：规则信息 + ATT&CK 标注 + 证据引用。
>
> **Dataset 约定**：
> - `event.dataset = "finding.raw"`：原始告警（Detect-first/Store-first 全收）
> - `event.dataset = "finding.canonical"`：融合去重后的规范告警（串链主要消费）

---

### 5.1 告警必填字段（除公共字段外）

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `event.severity` | `long` | ✅ | 严重程度（0-100） | `70` (高危), `30` (低危) |
| `rule.id` | `keyword` | ✅ | 规则唯一 ID | `R-DNS-001`, `T1055-001` |
| `rule.name` | `keyword` | ✅ | 规则名称（人类可读） | `DNS Tunnel Suspected` |
| `rule.ruleset` | `keyword` | ⭐ | 规则集/引擎 | `suricata`, `falco`, `opensearch-security` |
| `risk.score` | `float` | ⭐ | 风险分（0-100，可与 `event.severity` 映射） | `80.5` |
| `tags` | `keyword[]` | ⭐ | 标签（建议包含 ATT&CK） | `["attack.t1055", "attack.ta0005"]` |
| `threat.framework` | `keyword` | ✅ | 固定为 `MITRE ATT&CK` | `MITRE ATT&CK` |
| `threat.tactic.id` | `keyword` | ✅ | 战术 ID | `TA0005` |
| `threat.tactic.name` | `keyword` | ✅ | 战术名称 | `Defense Evasion` |
| `threat.technique.id` | `keyword` | ✅ | 技术ID | `T1055` |
| `threat.technique.name` | `keyword` | ✅ | 技术名称 | `Process Injection` |
| `threat.technique.subtechnique.id` | `keyword` | ⭕ | 子技术ID | `T1055.012` |

**约束**：
- `event.severity` 必须在 0-100 范围内
- `threat.*` 字段必须遵循 MITRE ATT&CK v12+ 规范
- `rule.id` 必须在规则集内唯一

---

### 5.2 `custom.*` 扩展字段（告警融合与证据引用）

**用途**：支持告警融合、去重、溯源的核心字段。

| 字段 | 类型 | 必填 | 说明 | 示例 |
|------|------|:----:|------|------|
| `custom.finding.stage` | `keyword` | ✅ | 告警阶段：`raw` 或 `canonical` | `raw`, `canonical` |
| `custom.finding.providers` | `keyword[]` | ✅ | 告警来源（检测引擎） | `["suricata"]`, `["falco", "security-analytics"]` |
| `custom.finding.fingerprint` | `keyword` | ⭐ | 融合指纹（raw→canonical 去重） | `fp-a1b2c3d4e5f6a7b8` |
| `custom.evidence.event_ids` | `keyword[]` | ⭐ | 证据事件列表（指向 Telemetry 的 `event.id`） | `["evt-123", "evt-456"]` |

**字段详解**：

#### `custom.finding.stage`
- `raw`：原始告警（来自检测引擎的直接输出）
- `canonical`：规范告警（融合去重后的唯一信号）

#### `custom.finding.providers`
- 标识哪些检测引擎生成了此告警
- 示例：
  - 端侧 Detect-first：`["falco"]`
  - 中心侧 Store-first：`["security-analytics"]`
  - 融合后：`["falco", "security-analytics"]`

#### `custom.finding.fingerprint`
- 用于 raw→canonical 融合去重
- 生成策略：`sha1(technique_id + host + (process_entity_id | dst_ip/domain | file_hash) + time_bucket)`
- 相同指纹的 Raw Findings 融合为一个 Canonical Finding

#### `custom.evidence.event_ids`
- 直接引用 Telemetry 的 `event.id` 列表
- 用于证据回溯：点击告警可跳转到原始事件详情

---

### 5.3 告警与 Telemetry 的关联键（至少一个）

**用途**：为了保证"可追溯"，告警里至少应存在一个可反查/可连边的关联键（越多越好）。

| 关联键 | 类型 | 适用场景 | 优先级 |
|--------|------|---------|:----:|
| `custom.evidence.event_ids` | `keyword[]` | 推荐：直接引用 Telemetry 的 `event.id` 列表 | ⭐⭐⭐⭐⭐ |
| `process.entity_id` | `keyword` | 主机侧行为/日志告警 | ⭐⭐⭐⭐ |
| `session.id` | `keyword` | 认证链告警 | ⭐⭐⭐⭐ |
| `flow.id` / `network.community_id` | `keyword` | 网络告警 | ⭐⭐⭐⭐ |
| `source.ip` / `destination.ip` / `dns.question.name` | `keyword/ip` | 弱关联（配合时间窗使用） | ⭐⭐ |

**约束**：
- 至少包含一个关联键
- 推荐使用 `custom.evidence.event_ids`（最直接）
- 弱关联键（如 IP）需要配合时间窗使用

---

## 6. JSON 示例（用于对齐接口与测试数据）

> **说明**：示例仅包含"最小必要字段"，实际入库可补充更多 ECS 字段（如 `observer.*`, `network.*`, `process.*`）。

---

### 6.1 `hostlog.auth`：SSH 登录成功（Telemetry）

```json
{
  "ecs": { "version": "9.2.0" },
  "@timestamp": "2026-01-12T03:21:10.123Z",
  "event": {
    "id": "evt-1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
    "kind": "event",
    "created": "2026-01-12T03:21:12.001Z",
    "ingested": "2026-01-12T03:21:12.900Z",
    "category": ["authentication"],
    "type": ["start"],
    "action": "user_login",
    "dataset": "hostlog.auth",
    "outcome": "success"
  },
  "host": { "id": "h-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "name": "victim-01" },
  "user": { "name": "alice" },
  "source": { "ip": "10.0.0.8" },
  "session": { "id": "sess-0123456789abcdef0123456789abcdef" },
  "agent": { "name": "wazuh-agent", "version": "4.0.0" }
}
```

---

### 6.2 `netflow.dns`：DNS 查询（Telemetry）

```json
{
  "ecs": { "version": "9.2.0" },
  "@timestamp": "2026-01-12T03:25:00.000Z",
  "event": {
    "id": "evt-9f8e7d6c5b4a392817160504a3b2c1d0e",
    "kind": "event",
    "created": "2026-01-12T03:25:00.010Z",
    "ingested": "2026-01-12T03:25:00.200Z",
    "category": ["network"],
    "type": ["info"],
    "action": "dns_query",
    "dataset": "netflow.dns"
  },
  "host": { "id": "h-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "name": "sensor-01" },
  "source": { "ip": "10.0.0.5", "port": 51514 },
  "destination": { "ip": "8.8.8.8", "port": 53 },
  "network": { "transport": "udp", "protocol": "dns" },
  "dns": { "question": { "name": "abc.def.example.com", "type": "TXT" } },
  "custom": { "dns": { "entropy": 4.2, "query_length": 180, "tunnel_score": 0.91 } },
  "agent": { "name": "suricata", "version": "7.0.0" }
}
```

---

### 6.3 `finding.raw`：可疑 DNS 隧道告警（Finding）

```json
{
  "ecs": { "version": "9.2.0" },
  "@timestamp": "2026-01-12T03:25:01.000Z",
  "event": {
    "id": "alrt-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "kind": "alert",
    "created": "2026-01-12T03:25:01.010Z",
    "ingested": "2026-01-12T03:25:01.200Z",
    "category": ["network"],
    "type": ["info"],
    "action": "dns_tunnel_suspected",
    "dataset": "finding.raw",
    "severity": 70
  },
  "host": { "id": "h-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "name": "sensor-01" },
  "rule": { "id": "R-DNS-001", "name": "DNS Tunnel Suspected" },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": { "id": "TA0011", "name": "Command and Control" },
    "technique": { "id": "T1071", "name": "Application Layer Protocol" }
  },
  "dns": { "question": { "name": "abc.def.example.com", "type": "TXT" } },
  "custom": {
    "finding": { "stage": "raw", "providers": ["suricata"], "fingerprint": "fp-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" },
    "evidence": { "event_ids": ["evt-9f8e7d6c5b4a392817160504a3b2c1d0e"] }
  },
  "agent": { "name": "suricata", "version": "7.0.0" }
}
```

---

## 7. 分工交付边界

### 7.1 同学1（主机日志）

**必须保证**：
- `session.id`、`user.*`、`source.ip`、`event.outcome` 完整
- 能做会话重建（登录 → 活动 → 注销）

**验收标准**：
- 能基于 `session.id` 重建完整的会话时间线
- 能基于 `user.name` + `source.ip` 检测异常登录

---

### 7.2 同学2（主机行为）

**必须保证**：
- `process.entity_id` 与 `process.parent.*` 完整
- 能做进程树/行为链

**验收标准**：
- 能基于 `process.entity_id` + `process.parent.entity_id` 构建完整的进程树
- 能基于 `event.action` 追踪行为链（如 `execve` → `connect` → `write`）

---

### 7.3 同学3（网络流量）

**必须保证**：
- `flow.id`/`network.community_id`、五元组、协议层字段（DNS/HTTP/ICMP）
- 能做会话重建与隧道检测

**验收标准**：
- 能基于 `flow.id` 重建完整的会话（开始 → 数据传输 → 结束）
- 能基于 `custom.dns.*` / `custom.icmp.*` 检测隧道行为

---

## 8. 可继续补充（实现过程中常用）

- **每个 dataset 的 JSON 示例样例**：本文已给出部分示例；如需落地采集/解析接口，可继续补齐 `hostlog.* / hostbehavior.* / netflow.* / finding.*` 全量示例。
- **OpenSearch 索引命名与映射建议**：见 `docs/03B-存储与图谱设计.md`（mapping 要点、字段类型建议、避免 text 聚合踩坑等）。
- **客户端 ↔ 中心机接口规范**：见 `docs/03C-客户端中心机接口规范.md`（注册、健康检查、数据拉取）。
