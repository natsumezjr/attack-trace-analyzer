# ECS 字段规范（ECS 子集 v1）

> 本文为 **ECS 字段规范（ECS 子集）**，由早期 “ECS 数据规范草案（v0.1）” 整理并与项目最终口径对齐（见 `docs/99-选型决策记录.md`）：  
> - ECS 版本固定为 **v9.2.0**（统一写 `ecs.version=9.2.0`）  
> - 所有自定义字段统一放入 **`custom.*`** 命名空间（避免污染 ECS 标准字段）  
> - 标记约定：`✅` = 必填；`⭐` = 建议；`⭕` = 可选  
>
> 覆盖范围：公共字段 + 三类数据源（主机日志/主机行为/网络流量）+ 检测告警（ATT&CK 映射），并满足时间对齐、会话重建、关联/溯源的最小字段需求。  
>
> 本文只描述“字段与语义”（用于数据归一化、接口约定、索引模板）；存储与建模（OpenSearch 索引划分、Neo4j 图模型等）见 `docs/03B-存储与图谱设计.md`。

---

## 0. 总体约束（全局口径）

### 0.1 事件类型（event.kind）

- `event.kind = "event"`：事实事件（Telemetry），不做善恶判断
- `event.kind = "alert"`：检测告警/发现（Finding），带规则/ATT&CK 标注

### 0.2 时间字段（三时间）

为满足“时间序列对齐 + 回放 + 排障”，统一采用 3 个时间：

- `@timestamp`：**对齐后的事件发生时间**（排序、时间窗关联以此为准）
- `event.created`：采集器/传感器**观察到事件**的时间（可用于衡量端侧延迟）
- `event.ingested`：中心侧**入库时间**（可用于衡量链路/管道延迟）

> 允许 `event.created` 与 `@timestamp` 相同（例如源数据只有一个时间戳时）。

### 0.3 标识字段（event.id / host.id / process.entity_id / session.id）

为确保跨源关联“可落地”，约定以下 ID 生成策略：

- `event.id`：**每条入库文档唯一**（Telemetry 和 Finding 都必须有）
  - 推荐：`uuidv4` 或 `sha1(source + raw_unique_key + @timestamp)`（只要稳定且不撞即可）
- `host.id`：建议作为跨源“最强关联键”
  - 若环境无法提供稳定主机 UUID，可采用：`sha1(host.name)`（注意：更换主机名会导致漂移）
- `process.entity_id`：同一主机内对“同一进程实例”的稳定标识（用于串进程树/行为链）
  - 推荐：`sha1(host.id + pid + process.start_time + process.executable)`（或传感器自带 entity_id）
- `session.id`：认证会话标识（用于登录会话重建）
  - 推荐：`sha1(host.id + user.name + source.ip + floor(@timestamp / Δt))`（Δt 可取 5–10 分钟，保证可复现）

---

## 1. 公共字段（所有数据源统一要求）

### 1.1 必填字段（所有事件）

> 说明：这里的“必填”指入库前必须补全；若上游没有对应信息，应通过推导/默认值补齐（例如生成 `event.id`、推导 `host.id`）。

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `ecs.version` | `keyword` | ✅ | 固定为 `9.2.0` |
| `@timestamp` | `date` | ✅ | 对齐后的发生时间 |
| `event.created` | `date` | ✅ | 采集器看到事件时间 |
| `event.ingested` | `date` | ✅ | 入库时间 |
| `event.id` | `keyword` | ✅ | 事件唯一 ID（Telemetry/Finding 都必须有） |
| `event.kind` | `keyword` | ✅ | `event` / `alert` |
| `event.category` | `keyword[]` | ✅ | ECS 事件大类（可多值） |
| `event.type` | `keyword[]` | ✅ | ECS 事件类型（可多值） |
| `event.action` | `keyword` | ✅ | 你们约定的动作枚举（用于检索/规则） |
| `event.dataset` | `keyword` | ✅ | 数据集（建议：`hostlog.* / hostbehavior.* / netflow.* / finding.*`） |
| `host.id` | `keyword` | ✅ | 主机唯一标识（见 0.3） |
| `host.name` | `keyword` | ✅ | 主机名（演示/检索更友好） |
| `agent.name` | `keyword` | ✅ | 采集器名称（如 `vector`/`fluent-bit`/`suricata` 等） |
| `agent.version` | `keyword` | ✅ | 采集器版本 |

### 1.2 强烈建议字段（强关联 / 回放 / 排障）

| 字段 | 类型（建议） | 建议 | 说明 |
|---|---|---:|---|
| `event.original` | `text` | ⭐ | 原始日志/原始 JSON（证据回放、截图） |
| `event.code` | `keyword` | ⭐ | EventID / syscall / 协议码等 |
| `event.outcome` | `keyword` | ⭐ | `success` / `failure`（认证/访问控制类强烈建议） |
| `message` | `text` | ⭐ | 人类可读摘要 |
| `process.entity_id` | `keyword` | ⭐ | 进程实例标识（存在进程语义的事件强烈建议） |
| `user.name` | `keyword` | ⭐ | 账号（存在认证/进程语义的事件强烈建议） |
| `related.user` | `keyword[]` | ⭐ | 聚合检索用：关联用户集合 |
| `related.ip` | `ip[]` | ⭐ | 聚合检索用：关联 IP 集合 |

---

## 2. Telemetry：主机日志（Host Logs，`hostlog.*`）

> 数据源：Wazuh（本项目主机日志采集只使用 Wazuh）。  
> 说明：Wazuh 侧输出的事件/告警需在归一化层映射为 ECS 子集字段（本文口径），再进入 OpenSearch 与后续关联/串链。

建议拆分 3 个 dataset：

- `hostlog.auth`：认证/登录（用于会话重建、横向移动）
- `hostlog.process`：进程事件（用于进程树与执行链）
- `hostlog.file_registry`：文件/注册表（用于敏感访问与持久化痕迹）

### 2.1 `hostlog.auth`（认证/登录）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostlog.auth` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `authentication` |
| `event.type` | `keyword[]` | ✅ | `start`（登录）/`end`（注销）/`info`（失败） |
| `event.action` | `keyword` | ✅ | `user_login` / `user_logout` / `logon_failed` |
| `event.outcome` | `keyword` | ✅ | `success` / `failure` |
| `user.name` | `keyword` | ✅ | 用户名/账号 |
| `source.ip` | `ip` | ✅ | 登录源 IP |
| `session.id` | `keyword` | ✅ | 会话 ID（见 0.3） |
| `authentication.method` | `keyword` | ⭐ | `password`/`ssh_key` 等 |
| `event.code` | `keyword` | ⭐ | Windows EventID / Linux auth code |

### 2.2 `hostlog.process`（进程事件）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostlog.process` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `process` |
| `event.type` | `keyword[]` | ✅ | `start`/`end` |
| `event.action` | `keyword` | ✅ | `process_start` / `process_end` |
| `process.pid` | `long` | ✅ | PID |
| `process.executable` | `keyword` | ✅ | 可执行文件路径 |
| `process.command_line` | `wildcard`/`text` | ⭐ | 命令行 |
| `process.parent.pid` | `long` | ⭐ | PPID |
| `process.parent.entity_id` | `keyword` | ⭐ | 父进程 entity_id（用于树分析） |
| `process.parent.executable` | `keyword` | ⭐ | 父进程可执行文件（若可获取） |
| `process.hash.sha256` | `keyword` | ⭐ | 可执行文件哈希（能算就算） |
| `process.entity_id` | `keyword` | ⭐ | 强烈建议补齐（见 0.3） |

### 2.3 `hostlog.file_registry`（文件/注册表）

#### 文件（`event.category` 包含 `file`）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.category` | `keyword[]` | ✅ | 建议包含 `file` |
| `event.type` | `keyword[]` | ✅ | `creation`/`deletion`/`change`/`access` |
| `event.action` | `keyword` | ✅ | `file_create`/`file_delete`/`file_read`/`file_write` |
| `file.path` | `keyword` | ✅ | 文件路径 |
| `process.entity_id` | `keyword` | ⭐ | 有则填（可将文件操作挂到进程） |
| `user.name` | `keyword` | ⭐ | 有则填 |

#### 注册表（Windows，`event.category` 包含 `registry`）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.category` | `keyword[]` | ✅ | 建议包含 `registry` |
| `event.type` | `keyword[]` | ✅ | `change` |
| `event.action` | `keyword` | ✅ | `registry_set_value` |
| `registry.path` | `keyword` | ✅ | 注册表路径 |
| `registry.value` | `keyword` | ⭐ | 键名 |
| `registry.data.strings` | `keyword[]` | ⭕ | 值内容（可选） |

---

## 3. Telemetry：主机行为（Host Behavior，`hostbehavior.*`）

> 数据源：Falco（本项目主机行为监控只使用 Falco）。  
> 落地建议：课程项目不做全量 syscall 入库，优先上报 **Falco 规则命中事件（alert）** 作为主机行为信号；字段仍按本节口径映射到 ECS 子集。

建议 dataset：

- `hostbehavior.syscall`：系统调用级行为（慎做全量，可只保留高价值）
- `hostbehavior.file`：文件访问（可从 syscall/传感器提取）
- `hostbehavior.memory`：内存注入/反射加载（偏告警/特征）

### 3.1 `hostbehavior.syscall`（syscall 模板）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostbehavior.syscall` |
| `event.action` | `keyword` | ✅ | `syscall_execve` / `syscall_open` / `syscall_connect` 等 |
| `event.code` | `keyword` | ✅ | syscall 名/号（如 `execve`/`2`） |
| `process.entity_id` | `keyword` | ✅ | 必须可用（串进程树/行为链的根） |
| `process.pid` | `long` | ✅ | PID |
| `process.executable` | `keyword` | ✅ | 可执行文件 |
| `process.parent.entity_id` | `keyword` | ⭐ | 建议补齐（进程树分析必需） |
| `user.name` | `keyword` | ⭐ | 建议补齐 |

### 3.2 `hostbehavior.file`（文件操作）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostbehavior.file` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `file` |
| `event.type` | `keyword[]` | ✅ | `access`/`change`/`creation`/`deletion` |
| `event.action` | `keyword` | ✅ | `file_read` / `file_write` 等 |
| `file.path` | `keyword` | ✅ | 文件路径 |
| `process.entity_id` | `keyword` | ✅ | 进程实例 |
| `user.name` | `keyword` | ⭐ | 建议补齐 |

### 3.3 `hostbehavior.memory`（注入/反射加载）

ECS 标准里没有“完美字段组”，本项目采用：ECS + `custom.*` 特征字段统一规范。

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `hostbehavior.memory` |
| `event.category` | `keyword[]` | ✅ | 建议为 `process` 或 `malware` |
| `event.type` | `keyword[]` | ✅ | `change` / `info` |
| `event.action` | `keyword` | ✅ | `process_injection` / `reflective_load` |
| `process.entity_id` | `keyword` | ✅ | 发起进程 |
| `custom.target.process.entity_id` | `keyword` | ⭐ | 被注入进程（若可获取） |
| `dll.path` | `keyword` | ⭕ | DLL 注入场景可填（可选） |
| `custom.memory.region_start` | `long` | ⭐ | 注入内存起始地址（若可获取） |
| `custom.memory.region_size` | `long` | ⭐ | 注入内存大小（若可获取） |
| `custom.memory.protection` | `keyword` | ⭐ | 如 `RWX`（若可获取） |

---

## 4. Telemetry：网络流量（Net Flow / Protocol，`netflow.*`）

建议 dataset：

- `netflow.flow`：五元组/会话 + 统计
- `netflow.dns`：DNS 查询（可加 DNS 隧道特征）
- `netflow.http`：HTTP 请求（可加隐蔽信道特征）
- `netflow.icmp`：ICMP（可加隧道特征）

### 4.1 `netflow.flow`（Flow/会话）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.flow` |
| `event.category` | `keyword[]` | ✅ | 建议包含 `network` |
| `event.type` | `keyword[]` | ✅ | `start`/`end`/`connection` |
| `event.action` | `keyword` | ✅ | `flow_start` / `flow_end` |
| `network.transport` | `keyword` | ✅ | `tcp`/`udp`/`icmp` |
| `network.protocol` | `keyword` | ✅ | `dns`/`http`/`tls` 等（可选但建议） |
| `source.ip` | `ip` | ✅ | 源 IP |
| `source.port` | `long` | ✅ | 源端口 |
| `destination.ip` | `ip` | ✅ | 目的 IP |
| `destination.port` | `long` | ✅ | 目的端口 |
| `flow.id` | `keyword` | ✅ | 流/会话 ID |
| `network.community_id` | `keyword` | ⭐ | community_id（Suricata 常见字段，建议） |
| `network.bytes` | `long` | ⭐ | 统计（建议） |
| `network.packets` | `long` | ⭐ | 统计（建议） |

### 4.2 `netflow.dns`（DNS）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.dns` |
| `network.protocol` | `keyword` | ✅ | `dns` |
| `dns.question.name` | `keyword` | ✅ | 查询域名 |
| `dns.question.type` | `keyword` | ✅ | 记录类型（如 `A`/`TXT`） |
| `dns.response_code` | `keyword` | ⭐ | 如 `NOERROR` |
| `event.action` | `keyword` | ✅ | `dns_query` / `dns_tunnel_suspected` |
| `custom.dns.entropy` | `float` | ⭕ | DNS 隧道特征（可选） |
| `custom.dns.query_length` | `long` | ⭕ | DNS 隧道特征（可选） |
| `custom.dns.tunnel_score` | `float` | ⭕ | DNS 隧道特征（可选） |

### 4.3 `netflow.http`（HTTP）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.http` |
| `network.protocol` | `keyword` | ✅ | `http` |
| `http.request.method` | `keyword` | ✅ | `GET`/`POST` 等 |
| `url.full` | `wildcard` | ✅ | 完整 URL |
| `url.domain` | `keyword` | ⭐ | 域名 |
| `http.response.status_code` | `long` | ⭐ | 状态码 |
| `user_agent.original` | `text` | ⭕ | UA（可选） |
| `event.action` | `keyword` | ✅ | `http_request` / `http_covert_channel_suspected` |

### 4.4 `netflow.icmp`（ICMP）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.dataset` | `keyword` | ✅ | 固定为 `netflow.icmp` |
| `network.transport` | `keyword` | ✅ | `icmp` |
| `icmp.type` | `long` | ✅ | ICMP type |
| `icmp.code` | `long` | ✅ | ICMP code |
| `event.action` | `keyword` | ✅ | `icmp_echo` / `icmp_tunnel_suspected` |
| `custom.icmp.payload_size` | `long` | ⭕ | 载荷大小（隧道特征，可选） |

---

## 5. Findings/Alerts（检测告警，`finding.*` + `custom.*`）

告警文档同样遵循 ECS 子集（见 1），但必须额外携带：规则信息 + ATT&CK 标注 + 证据引用。

### 5.1 `finding.raw` / `finding.canonical`（数据集约定）

- `event.dataset = "finding.raw"`：原始告警（Detect-first/Store-first 全收）
- `event.dataset = "finding.canonical"`：融合去重后的规范告警（串链主要消费）

### 5.2 告警必填字段（除公共字段外）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `event.severity` | `integer` | ✅ | 统一为 0–100 |
| `rule.id` | `keyword` | ✅ | 规则唯一 ID |
| `rule.name` | `keyword` | ✅ | 规则名 |
| `rule.ruleset` | `keyword` | ⭐ | 规则集/引擎（如 `opensearch-security`） |
| `risk.score` | `float` | ⭐ | 0–100 风险分（可与 `event.severity` 做映射） |
| `tags` | `keyword[]` | ⭐ | 建议包含 `attack.txxxx` / `attack.taxxxx` 便于筛选 |
| `threat.framework` | `keyword` | ✅ | 固定为 `MITRE ATT&CK` |
| `threat.tactic.id` | `keyword` | ✅ | 如 `TA0005` |
| `threat.tactic.name` | `keyword` | ✅ | 如 `Defense Evasion` |
| `threat.technique.id` | `keyword` | ✅ | 如 `T1055` |
| `threat.technique.name` | `keyword` | ✅ | 如 `Process Injection` |
| `threat.technique.subtechnique.id` | `keyword` | ⭕ | 如 `T1055.012` |

### 5.3 `custom.*` 扩展字段（告警融合与证据引用）

| 字段 | 类型（建议） | 必填 | 说明 |
|---|---|---:|---|
| `custom.finding.stage` | `keyword` | ✅ | `raw` / `canonical` |
| `custom.finding.providers` | `keyword[]` | ✅ | 告警来源（`suricata`/`falco`/`security-analytics`…） |
| `custom.finding.fingerprint` | `keyword` | ⭐ | raw→canonical 融合指纹（建议） |
| `custom.confidence` | `float` | ⭕ | 置信度 0–1（可选） |
| `custom.evidence.event_ids` | `keyword[]` | ⭐ | 证据事件列表（指向 Telemetry 的 `event.id`） |
| `custom.evidence.query` | `text` | ⭕ | 预留：生成告警/关联用的检索语句（v1 可不实现） |

### 5.4 告警与 Telemetry 的关联键（至少一个）

为了保证“可追溯”，告警里至少应存在一个可反查/可连边的关联键（越多越好）：

- `custom.evidence.event_ids`（推荐：直接引用 Telemetry 的 `event.id` 列表）
- `process.entity_id`（主机侧行为/日志告警）
- `session.id`（认证链告警）
- `flow.id` 或 `network.community_id`（网络告警）
- `event.id`（Telemetry 的事件唯一 ID；在告警中通常以 `custom.evidence.event_ids` 形式承载）
- `source.ip` / `destination.ip` / `dns.question.name`（弱关联，配合时间窗使用）

---

## 6. JSON 示例（用于对齐接口与测试数据）

> 示例仅包含“最小必要字段”，实际入库可补充更多 ECS 字段（如 `observer.* / network.* / process.*`）。

### 6.1 `hostlog.auth`：SSH 登录成功（Telemetry）

```json
{
  "ecs": { "version": "9.2.0" },
  "@timestamp": "2026-01-12T03:21:10.123Z",
  "event": {
    "id": "evt-1b2c3d",
    "kind": "event",
    "created": "2026-01-12T03:21:12.001Z",
    "ingested": "2026-01-12T03:21:12.900Z",
    "category": ["authentication"],
    "type": ["start"],
    "action": "user_login",
    "dataset": "hostlog.auth",
    "outcome": "success"
  },
  "host": { "id": "h-aaa", "name": "victim-01" },
  "user": { "name": "alice" },
  "source": { "ip": "10.0.0.8" },
  "session": { "id": "sess-xyz" },
  "agent": { "name": "wazuh-agent", "version": "4.0.0" }
}
```

### 6.2 `netflow.dns`：DNS 查询（Telemetry）

```json
{
  "ecs": { "version": "9.2.0" },
  "@timestamp": "2026-01-12T03:25:00.000Z",
  "event": {
    "id": "evt-9f8e7d",
    "kind": "event",
    "created": "2026-01-12T03:25:00.010Z",
    "ingested": "2026-01-12T03:25:00.200Z",
    "category": ["network"],
    "type": ["info"],
    "action": "dns_query",
    "dataset": "netflow.dns"
  },
  "host": { "id": "h-aaa", "name": "sensor-01" },
  "source": { "ip": "10.0.0.5", "port": 51514 },
  "destination": { "ip": "8.8.8.8", "port": 53 },
  "network": { "transport": "udp", "protocol": "dns" },
  "dns": { "question": { "name": "abc.def.example.com", "type": "TXT" } },
  "custom": { "dns": { "entropy": 4.2, "query_length": 180, "tunnel_score": 0.91 } },
  "agent": { "name": "suricata", "version": "7.0.0" }
}
```

### 6.3 `finding.raw`：可疑 DNS 隧道告警（Finding）

```json
{
  "ecs": { "version": "9.2.0" },
  "@timestamp": "2026-01-12T03:25:01.000Z",
  "event": {
    "id": "alrt-123",
    "kind": "alert",
    "created": "2026-01-12T03:25:01.010Z",
    "ingested": "2026-01-12T03:25:01.200Z",
    "category": ["network"],
    "type": ["info"],
    "action": "dns_tunnel_suspected",
    "dataset": "finding.raw",
    "severity": 70
  },
  "host": { "id": "h-aaa", "name": "sensor-01" },
  "rule": { "id": "R-DNS-001", "name": "DNS Tunnel Suspected" },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": { "id": "TA0011", "name": "Command and Control" },
    "technique": { "id": "T1071", "name": "Application Layer Protocol" }
  },
  "dns": { "question": { "name": "abc.def.example.com", "type": "TXT" } },
  "custom": {
    "finding": { "stage": "raw", "providers": ["suricata"], "fingerprint": "fp-aaa" },
    "confidence": 0.7,
    "evidence": { "event_ids": ["evt-9f8e7d"] }
  },
  "agent": { "name": "suricata", "version": "7.0.0" }
}
```

---

## 7. 分工交付边界（写进分工/验收最清楚）

- **同学1（主机日志）**：必须保证 `session.id`、`user.*`、`source.ip`、`event.outcome` 完整，能做会话重建。
- **同学2（主机行为）**：必须保证 `process.entity_id` 与 `process.parent.*` 完整，能做进程树/行为链。
- **同学3（网络流量）**：必须保证 `flow.id`/`network.community_id`、五元组、协议层字段（DNS/HTTP/ICMP），能做会话重建与隧道检测。

---

## 8. 可继续补充（实现过程中常用）

- **每个 dataset 的 JSON 示例样例**：本文已给出部分示例；如需落地采集/解析接口，可继续补齐 `hostlog.* / hostbehavior.* / netflow.* / finding.*` 全量示例。
- **OpenSearch 索引命名与映射建议**：见 `docs/03B-存储与图谱设计.md`（mapping 要点、字段类型建议、避免 text 聚合踩坑等）。
