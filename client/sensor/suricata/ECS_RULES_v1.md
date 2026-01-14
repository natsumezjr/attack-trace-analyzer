下面给你一份可以直接放进你们“数据规范/接口规范”文档里的 **ECS 数据规范草案（v0.1）**：按 **公共字段 + 三类数据源（主机日志/主机行为/网络流量）+ 检测告警(ATT&CK 映射)** 来写，且覆盖你们实验要求里的时间对齐、会话重建、实体/关系关联、ATT&CK 映射与关联分析目标。

> 说明：
> 
> - “必填”= 必须存在且有意义；“建议”= 尽量填；“可选”= 有就填。
> - 自定义字段统一放到 `custom.*` 命名空间，避免污染 ECS 标准字段。
> - 所有事件都应写入 `ecs.version`（例如 `9.2.0`）。

---

# 1. 总体约束与公共字段（所有数据源必填/建议）

## 1.1 必填公共字段（所有事件）

| 字段 | 类型 | 必填 | 示例 | 说明 |
| --- | --- | --- | --- | --- |
| `ecs.version` | keyword | ✅ | `9.2.0` | ECS 版本 |
| `@timestamp` | date | ✅ | `2026-01-12T03:21:10.123Z` | **对齐后的事件发生时间**（满足时间序列对齐） |
| `event.created` | date | ✅ | `2026-01-12T03:21:12.001Z` | 采集器看到事件的时间 |
| `event.ingested` | date | ✅ | `2026-01-12T03:21:12.900Z` | 服务端入库时间 |
| `event.kind` | keyword | ✅ | `event` / `alert` | 原始事件用 `event`，检测告警用 `alert` |
| `event.category` | keyword[] | ✅ | `["process"]` | ECS 事件大类（可多值） |
| `event.type` | keyword[] | ✅ | `["start"]` | 事件类型（可多值） |
| `event.action` | keyword | ✅ | `user_login` | **你们自定义动作枚举**（规则/检索最好用） |
| `event.dataset` | keyword | ✅ | `hostlog.auth` | 建议统一：`hostlog.* / hostbehavior.* / netflow.*` |
| `host.id` | keyword | ✅ | `f3c1...` | 主机唯一标识（跨源关联关键） |
| `host.name` | keyword | ✅ | `PC-01` | 主机名 |
| `agent.name` | keyword | ✅ | `collector-win` | 采集器名称 |
| `agent.version` | keyword | ✅ | `0.3.1` | 采集器版本 |

## 1.2 强烈建议公共字段（强关联/排障）

| 字段 | 类型 | 建议 | 示例 | 说明 |
| --- | --- | --- | --- | --- |
| `event.original` | text | ✅ | `...raw log...` | 原始内容（审计/回放） |
| `event.code` | keyword | ⭐ | `4624` / `execve` | EventID / syscall / 协议码 |
| `event.outcome` | keyword | ⭐ | `success`/`failure` | 认证/访问类必填 |
| `message` | text | ⭐ | `User login success` | 人类可读摘要 |
| `related.user` | keyword[] | ⭐ | `["alice"]` | 关联实体（便于跨索引检索） |
| `related.ip` | ip[] | ⭐ | `["1.2.3.4"]` | 同上 |
| `process.entity_id` | keyword | ⭐ | `p-...` | **跨日志/行为把同一进程串起来的关键** |

---

# 2. 数据源（1）：主机日志采集与分析（Host Logs）

覆盖你们要求的：时间对齐、范式解析、关键信息提取、登录会话重建。

建议分 3 个 dataset：`hostlog.auth` / `hostlog.process` / `hostlog.file_registry`

## 2.1 认证/登录日志（用于会话重建）

| 字段 | 类型 | 必填 | 示例 | 说明 |
| --- | --- | --- | --- | --- |
| `event.category` | keyword[] | ✅ | `["authentication"]` |  |
| `event.type` | keyword[] | ✅ | `["start"]` / `["end"]` | 登录=start；注销=end |
| `event.action` | keyword | ✅ | `user_login` / `user_logout` / `logon_failed` | 固定枚举 |
| `event.outcome` | keyword | ✅ | `success` |  |
| `user.name` | keyword | ✅ | `alice` | 关键实体：用户 |
| `source.ip` | ip | ✅ | `10.0.0.8` | 关键实体：源 IP |
| `session.id` | keyword | ✅ | `sess-...` | 用于重建会话时间线 |
| `authentication.method` | keyword | 建议 | `password`/`ssh_key` | 有就填 |
| `event.code` | keyword | 建议 | `4624` | Windows EventID / Linux auth code |

> session.id 生成建议：
> 
> 
> `hash(host.id + user.name + source.ip + first_login_timestamp_bucket)`，确保稳定且可复现。
> 

## 2.2 进程类日志（从日志里抽取进程实体）

| 字段 | 类型 | 必填 | 示例 | 说明 |
| --- | --- | --- | --- | --- |
| `event.category` | keyword[] | ✅ | `["process"]` |  |
| `event.type` | keyword[] | ✅ | `["start"]` / `["end"]` |  |
| `event.action` | keyword | ✅ | `process_start` | 固定枚举 |
| `process.pid` | long | ✅ | `1234` |  |
| `process.executable` | keyword | ✅ | `C:\Windows\System32\cmd.exe` |  |
| `process.command_line` | wildcard/text | 建议 | `cmd.exe /c whoami` |  |
| `process.parent.pid` | long | 建议 | `456` |  |
| `process.parent.executable` | keyword | 建议 | `explorer.exe` |  |
| `process.hash.sha256` | keyword | 建议 | `...` | 能算就算 |

## 2.3 文件/注册表日志（关键实体提取）

### 文件

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `event.category` | keyword[] | ✅ | `["file"]` |
| `event.type` | keyword[] | ✅ | `["creation"]` / `["deletion"]` / `["change"]` / `["access"]` |
| `event.action` | keyword | ✅ | `file_create` / `file_delete` / `file_read` / `file_write` |
| `file.path` | keyword | ✅ | `/etc/passwd` |
| `file.name` | keyword | 建议 | `passwd` |
| `user.name` | keyword | 建议 | `root` |
| `process.entity_id` | keyword | 建议 | `p-...` |

### 注册表（Windows）

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `event.category` | keyword[] | ✅ | `["registry"]` |
| `event.type` | keyword[] | ✅ | `["change"]` |
| `event.action` | keyword | ✅ | `registry_set_value` |
| `registry.path` | keyword | ✅ | `HKCU\Software\...` |
| `registry.value` | keyword | 建议 | `Run` |
| `registry.data.strings` | keyword[] | 可选 | `["..."]` |

---

# 3. 数据源（2）：主机行为监控（Host Behavior / Syscall）

覆盖：syscall 拦截、进程树、文件操作、内存注入/反射加载。

建议 dataset：`hostbehavior.syscall` / `hostbehavior.file` / `hostbehavior.memory`

## 3.1 syscall 事件通用模板（每条行为都挂到进程）

| 字段 | 类型 | 必填 | 示例 | 说明 |
| --- | --- | --- | --- | --- |
| `event.dataset` | keyword | ✅ | `hostbehavior.syscall` |  |
| `event.action` | keyword | ✅ | `syscall_execve` / `syscall_open` / `syscall_connect` | 固定枚举 |
| `event.code` | keyword | ✅ | `execve` / `2` | syscall 名/号 |
| `process.entity_id` | keyword | ✅ | `p-...` | **必须** |
| `process.pid` | long | ✅ | `4321` |  |
| `process.executable` | keyword | ✅ | `/usr/bin/curl` |  |
| `process.parent.entity_id` | keyword | 建议 | `p-...` | 进程树分析必需 |
| `user.name` | keyword | 建议 | `alice` |  |

## 3.2 文件操作（来自 syscall 或内核监控）

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `event.dataset` | keyword | ✅ | `hostbehavior.file` |
| `event.category` | keyword[] | ✅ | `["file"]` |
| `event.type` | keyword[] | ✅ | `["access"]` / `["change"]` / `["creation"]` / `["deletion"]` |
| `event.action` | keyword | ✅ | `file_read` / `file_write` |
| `file.path` | keyword | ✅ | `/home/alice/.ssh/id_rsa` |
| `process.entity_id` | keyword | ✅ | `p-...` |
| `user.name` | keyword | 建议 | `alice` |

## 3.3 内存行为（注入/反射加载）

ECS 标准里没有“完美字段组”，建议采用：ECS + `custom.*` 特征字段统一规范。

| 字段 | 类型 | 必填 | 示例 | 说明 |
| --- | --- | --- | --- | --- |
| `event.dataset` | keyword | ✅ | `hostbehavior.memory` |  |
| `event.category` | keyword[] | ✅ | `["process"]` 或 `["malware"]` |  |
| `event.type` | keyword[] | ✅ | `["change"]` / `["info"]` |  |
| `event.action` | keyword | ✅ | `process_injection` / `reflective_load` | 固定枚举 |
| `process.entity_id` | keyword | ✅ | `p-src...` | 发起进程 |
| `custom.target.process.entity_id` | keyword | 建议 | `p-dst...` | 被注入进程（建议自定义） |
| `dll.path` | keyword | 可选 | `C:\...\evil.dll` | DLL 注入场景 |
| `custom.memory.region_start` | long | 建议 | `140737...` |  |
| `custom.memory.region_size` | long | 建议 | `4096` |  |
| `custom.memory.protection` | keyword | 建议 | `RWX` |  |

---

# 4. 数据源（3）：网络流量分析（Net Flow / Protocol）

覆盖：抓包解析、异常协议建模、会话重建、隐蔽信道检测（DNS/HTTP/ICMP）。

建议 dataset：`netflow.flow` / `netflow.dns` / `netflow.http` / `netflow.icmp`

## 4.1 Flow/会话（五元组 + 统计）

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `event.dataset` | keyword | ✅ | `netflow.flow` |
| `event.category` | keyword[] | ✅ | `["network"]` |
| `event.type` | keyword[] | ✅ | `["start"]` / `["end"]` / `["connection"]` |
| `event.action` | keyword | ✅ | `flow_start` / `flow_end` |
| `network.transport` | keyword | ✅ | `tcp` |
| `network.protocol` | keyword | ✅ | `dns` / `http` |
| `source.ip` | ip | ✅ | `10.0.0.5` |
| `source.port` | long | ✅ | `51514` |
| `destination.ip` | ip | ✅ | `8.8.8.8` |
| `destination.port` | long | ✅ | `53` |
| `flow.id` | keyword | ✅ | `flow-...` |
| `network.community_id` | keyword | 建议 | `1:...` |
| `network.bytes` | long | 建议 | `12345` |
| `network.packets` | long | 建议 | `120` |

## 4.2 DNS（含 DNS 隧道检测特征）

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `event.dataset` | keyword | ✅ | `netflow.dns` |
| `network.protocol` | keyword | ✅ | `dns` |
| `dns.question.name` | keyword | ✅ | `abc.def.example.com` |
| `dns.question.type` | keyword | ✅ | `TXT` |
| `dns.response_code` | keyword | 建议 | `NOERROR` |
| `event.action` | keyword | ✅ | `dns_query` / `dns_tunnel_suspected` |
| `custom.dns.entropy` | float | 可选 | `4.2` |
| `custom.dns.query_length` | long | 可选 | `180` |
| `custom.dns.tunnel_score` | float | 可选 | `0.91` |

## 4.3 HTTP（含隐蔽信道）

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `event.dataset` | keyword | ✅ | `netflow.http` |
| `network.protocol` | keyword | ✅ | `http` |
| `http.request.method` | keyword | ✅ | `POST` |
| `url.full` | wildcard | ✅ | `http://a.com/p` |
| `url.domain` | keyword | 建议 | `a.com` |
| `http.response.status_code` | long | 建议 | `200` |
| `user_agent.original` | text | 可选 | `curl/7.88` |
| `event.action` | keyword | ✅ | `http_request` / `http_covert_channel_suspected` |

## 4.4 ICMP（含 ICMP 隧道）

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `event.dataset` | keyword | ✅ | `netflow.icmp` |
| `network.transport` | keyword | ✅ | `icmp` |
| `icmp.type` | long | ✅ | `8` |
| `icmp.code` | long | ✅ | `0` |
| `event.action` | keyword | ✅ | `icmp_echo` / `icmp_tunnel_suspected` |
| `custom.icmp.payload_size` | long | 可选 | `1400` |

---

# 5. 检测事件（Alert）与 ATT&CK 映射规范（统一输出格式）

你们后续“调用 OpenSearch Security 分析数据，将检测事件映射到 ATT&CK 阶段”的部分，建议所有告警遵循同一套字段：

## 5.1 告警必填字段

| 字段 | 类型 | 必填 | 示例 | 说明 |
| --- | --- | --- | --- | --- |
| `event.kind` | keyword | ✅ | `alert` |  |
| `event.category` | keyword[] | ✅ | `["process"]` | 告警归类 |
| `event.type` | keyword[] | ✅ | `["info"]` |  |
| `event.action` | keyword | ✅ | `detect_process_injection` | 检测规则动作名 |
| `rule.id` | keyword | ✅ | `R-0012` | 规则唯一 ID |
| `rule.name` | keyword | ✅ | `Process Injection` | 规则名 |
| `rule.ruleset` | keyword | 建议 | `opensearch-security` |  |
| `risk.score` | float | 建议 | `80` | 0-100 |
| `tags` | keyword[] | 建议 | `["attack.t1055","attack.ta0005"]` | 方便筛选 |

## 5.2 ATT&CK 映射字段（统一用 threat.*）

| 字段 | 类型 | 必填 | 示例 |
| --- | --- | --- | --- |
| `threat.framework` | keyword | ✅ | `MITRE ATT&CK` |
| `threat.tactic.id` | keyword | ✅ | `TA0005` |
| `threat.tactic.name` | keyword | ✅ | `Defense Evasion` |
| `threat.technique.id` | keyword | ✅ | `T1055` |
| `threat.technique.name` | keyword | ✅ | `Process Injection` |
| `threat.technique.subtechnique.id` | keyword | 可选 | `T1055.012` |

## 5.3 告警与原始事件的关联（必须能“追溯”）

告警里至少带一个可反查的关联键：

- `process.entity_id`（主机侧行为/日志告警）
- `session.id`（认证链告警）
- `flow.id` 或 `network.community_id`（网络告警）
- `event.id`（若你们为每条原始事件生成唯一 id）

---

# 6. 三位同学的“交付边界”（写进分工最清楚）

- **同学1（主机日志）**：必须保证 `session.id`、`user.*`、`source.ip`、`event.outcome` 完整，能做会话重建。
- **同学2（主机行为）**：必须保证 `process.entity_id` 与 `process.parent.*` 完整，能做进程树/行为链。
- **同学3（网络流量）**：必须保证 `flow.id`/`network.community_id`、五元组、协议层字段（dns/http/icmp），能做会话重建与隧道检测。

---

如果你们后端接口已经定了（例如 RESTful 上报 JSON），我也可以基于这份规范再补两样最实用的东西（不需要你再提供额外信息，我会按常见实现给默认）：

1. **每个 dataset 的 JSON 示例样例（含必填/建议字段）**
2. **OpenSearch 索引命名与映射建议**（比如按 `event.dataset` 分 index pattern、哪些字段要 keyword/wildcard、如何避免 text 聚合问题）