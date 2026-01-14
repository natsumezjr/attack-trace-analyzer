# 实体图谱规范（v2）

## 0. 输入与输出边界（权威）

### 0.1 图谱输入（上游）

图谱抽取只接受两类上游 ECS 文档：

1. Telemetry：`event.kind="event"`
2. Canonical Finding：`event.kind="alert"` 且 `event.dataset="finding.canonical"`

任何 Raw Finding 均不得直接入图。

### 0.2 图谱输出（下游）

- 图数据库：Neo4j（权威存储）
- 图算法：Neo4j GDS（时间窗投影 + 加权最短路）

### 0.3 图谱不建模的对象（固定取舍）

- 不创建 `NetConn/Flow` 节点：会话键（`flow.id`、`network.community_id` 等）只作为边属性保存。
- `session` 不作为独立节点长期保存：会话 ID 只作为边属性或事件字段使用。

### 0.4 Node UID（用于 API 与前端展示）

系统使用统一的 Node UID 字符串表达节点，格式固定为：

- 单键：`<Label>:<key_field>=<value>`  
- 复合键：`<Label>:k1=v1;k2=v2`（按 key 字段名排序）

示例：

- `Host:host.id=h-1111111111111111`
- `User:user.id=u-abc`
- `User:host.id=h-111...;user.name=alice`
- `File:host.id=h-111...;file.path=/etc/passwd`

UID 的构造与解析规则必须与后端实现一致（见 `backend/app/services/neo4j/models.py`）。

## 1. 节点（Node）规范

### 1.1 节点类型总览

| Label | 含义 | 唯一键（Key） |
|---|---|---|
| `Host` | 主机 | `host.id` |
| `User` | 用户 | `user.id`；当缺失时使用 `host.id + user.name` |
| `Process` | 进程实例 | `process.entity_id` |
| `File` | 文件（主机内视角） | `host.id + file.path` |
| `IP` | IP 地址 | `ip` |
| `Domain` | 域名 | `domain.name` |

### 1.2 各节点字段要求

#### 1.2.1 Host

- Key：`host.id`
- 必须属性：
  - `host.id`
  - `host.name`
- 生成规则：
  - 若事件中缺失 `host.id`，必须按 `51-ECS字段规范.md` 生成并回填。

#### 1.2.2 User

- Key 选择规则（严格优先级）：
  1) 当存在 `user.id`：Key = `user.id`
  2) 当缺失 `user.id`：Key = `host.id + user.name`
- 必须属性：
  - `user.name`
  - `host.id`（当使用复合键时必须存在）

#### 1.2.3 Process

- Key：`process.entity_id`
- 必须属性：
  - `process.entity_id`
  - `process.pid`
  - `process.executable`（或等价字段）
- 生成规则：
  - 当缺失 `process.entity_id` 时必须按 `51-ECS字段规范.md` 生成并回填。

#### 1.2.4 File

- Key：`host.id + file.path`
- 必须属性：
  - `host.id`
  - `file.path`
- 允许属性：
  - `file.hash.sha256`（当输入存在时必须写入）

#### 1.2.5 IP

- Key：`ip`（IPv4/IPv6 字符串）
- 必须属性：
  - `ip`

#### 1.2.6 Domain

- Key：`domain.name`（FQDN）
- 必须属性：
  - `domain.name`

Domain 的来源字段映射规则：

- 当存在 `dns.question.name`：`domain.name = dns.question.name`
- 否则当存在 `url.domain`：`domain.name = url.domain`

## 2. 边（Edge）规范

### 2.1 边类型总览

| RelType | 语义 | from → to |
|---|---|---|
| `LOGON` | 用户登录主机 | `User → Host` |
| `RUNS_ON` | 进程归属主机（结构边） | `Process → Host` |
| `SPAWN` | 父进程创建子进程 | `Process → Process` |
| `FILE_ACCESS` | 文件访问 | `Process → File`；当缺失进程时为 `Host → File` |
| `NET_CONNECT` | 发起网络连接 | `Process → IP`；当缺失进程时为 `Host → IP` |
| `DNS_QUERY` | 发起 DNS 查询 | `Process → Domain`；当缺失进程时为 `Host → Domain` |
| `RESOLVES_TO` | 域名解析到 IP | `Domain → IP` |
| `HAS_IP` | 主机拥有 IP（结构边） | `Host → IP` |

### 2.2 边属性（必须写入）

每条边必须写入：

- `ts`：字符串时间戳，等同 `@timestamp`
- `ts_float`：数值时间戳（秒，float）
- `custom.evidence.event_ids[]`：证据事件 ID 列表
- `event.id` / `event.kind` / `event.dataset`：来源标识

当边来自 Canonical Finding 时必须额外写入：

- `is_alarm=true`
- `rule.*`、`threat.*`、`event.severity`、`custom.finding.*`

### 2.3 边属性（关系特定）

- `FILE_ACCESS`：`op`（从 `event.action` 映射为 `read/write/execute`）
- `NET_CONNECT`：`destination.port`、`network.transport`、`network.protocol`、`flow.id`、`network.community_id`
- `DNS_QUERY`：`dns.question.type`、`dns.response_code`、`custom.dns.entropy`、`custom.dns.query_length`、`custom.dns.tunnel_score`

## 3. 抽取规则（按 dataset）

> 抽取规则必须与后端实现一致（当前实现见 `backend/app/services/neo4j/ecs_ingest.py`）。

### 3.1 `hostlog.auth` → `LOGON`

触发条件：

- `event.dataset == "hostlog.auth"`，或 `event.category[]` 包含 `authentication`

抽取：

- `User → Host`：`LOGON`

### 3.2 `hostlog.process` → `RUNS_ON` 与 `SPAWN`

触发条件：

- `event.dataset == "hostlog.process"`，或 `event.category[]` 包含 `process`

抽取：

- `Process → Host`：`RUNS_ON`
- 当存在 `process.parent.entity_id`：`Process(parent) → Process(child)`：`SPAWN`

### 3.3 `hostbehavior.file` / `hostlog.file_registry` → `FILE_ACCESS`

触发条件：

- `event.dataset == "hostbehavior.file"`，或 `event.dataset == "hostlog.file_registry"`，或 `event.category[]` 包含 `file`

抽取：

- 当存在 `process.entity_id`：`Process → File`：`FILE_ACCESS`
- 当缺失 `process.entity_id` 且 `event.dataset == "hostlog.file_registry"`：`Host → File`：`FILE_ACCESS`

### 3.4 `netflow.flow` / 网络类告警 → `NET_CONNECT`

触发条件（任一）：

- `event.dataset == "netflow.flow"`
- `event.dataset == "hostbehavior.syscall"` 且 `event.action` 或 `event.code` 表示 `connect`
- `event.kind == "alert"` 且 `event.category[]` 包含 `network`

抽取：

- 当存在 `process.entity_id`：`Process → IP(destination.ip)`：`NET_CONNECT`
- 当缺失 `process.entity_id`：`Host → IP(destination.ip)`：`NET_CONNECT`

### 3.5 `netflow.dns` / DNS 类告警 → `DNS_QUERY` 与 `RESOLVES_TO`

触发条件（任一）：

- `event.dataset == "netflow.dns"`
- `event.kind == "alert"` 且存在 `dns.question.name`，且 `event.action` 包含 `dns`

抽取：

- `Host/Process → Domain`：`DNS_QUERY`
  - 当存在 `process.entity_id`：使用 `Process` 作为源节点
  - 否则使用 `Host` 作为源节点
- 对每个 DNS answer IP：`Domain → IP`：`RESOLVES_TO`

### 3.6 `HAS_IP`

触发条件：

- 事件包含 `host.ip[]`

抽取：

- `Host → IP`：`HAS_IP`
