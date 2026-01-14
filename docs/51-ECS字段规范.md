# ECS 字段规范（ECS 子集 v1.0）

## 0. 全局约束（权威）

### 0.1 ECS 版本

- 所有事件必须写入 `ecs.version="9.2.0"`。

### 0.2 事件分类（event.kind）

`event.kind` 只允许取以下值：

- `event`：Telemetry（事实事件）
- `alert`：Finding（告警/发现）

中心机入库路由依赖 `event.kind`，任何其它取值都必须在入库前被丢弃。

### 0.3 Dataset 命名体系（event.dataset）

系统只承认以下 dataset 命名体系：

#### Telemetry datasets

- `hostlog.auth`：认证/登录
- `hostlog.process`：进程事件
- `hostlog.file_registry`：文件与注册表
- `hostbehavior.syscall`：主机行为（系统调用）
- `hostbehavior.file`：主机行为（文件访问）
- `hostbehavior.memory`：主机行为（内存/注入）
- `netflow.flow`：网络流（五元组）
- `netflow.dns`：DNS
- `netflow.http`：HTTP
- `netflow.tls`：TLS
- `netflow.icmp`：ICMP

#### Finding datasets

- Raw Finding：`finding.raw.<provider>`
  - provider 取值固定为：`falco` / `suricata` / `filebeat_sigma` / `security_analytics`
- Canonical Finding：`finding.canonical`

### 0.4 三时间字段（必须存在）

所有事件必须同时具备：

| 字段 | 语义 | 规则 |
|---|---|---|
| `@timestamp` | 对齐后的事件发生时间 | 主时间轴；缺失则必须从 `event.created` 推导；仍缺失则丢弃 |
| `event.created` | 采集端观察到事件的时间 | 缺失则回填为 `@timestamp` |
| `event.ingested` | 中心机入库时间 | 中心机写入时覆盖为当前时间 |

时间格式统一为 ISO 8601（UTC，`Z` 结尾）。

### 0.5 事件唯一标识（event.id）

#### 0.5.1 全局规则

- 所有事件必须具备 `event.id`。
- `event.id` 必须稳定：同一条事件被重复拉取/重复入库时 `event.id` 不变。
- 中心机以 `event.id` 作为幂等去重键。

#### 0.5.2 客户机侧生成规则（固定）

客户机侧对外提供拉取接口时，必须为每条返回的 ECS 文档生成稳定 `event.id`。

当上游事件本身已经包含 `event.id` 时：直接透传，不得覆盖。  
当上游事件缺失 `event.id` 时：按以下固定规则生成：

- `event.id = "evt-" + sha1(raw_payload_bytes)[:16]`

其中：

- `raw_payload_bytes`：客户机从 RabbitMQ 读取到的**原始消息体字节序列**（JSON），在做任何字段补齐/结构规范化之前取值。

> 说明：该规则无需依赖本地数据库自增主键，且对“同一条消息被重复投递/重复拉取”的场景保持稳定，可作为中心机幂等去重键。

### 0.6 字段命名形态（嵌套与点号）

系统在 JSON 表达上允许两种形态：

1) 嵌套对象：`{"event": {"id": "...", "kind": "event"}}`  
2) 点号扁平键：`{"event.id": "...", "event.kind": "event"}`  

中心机入库前必须把输入规范化为“嵌套对象优先”的形态，并保证最终语义一致。

## 1. 公共字段（所有事件必须具备）

下表字段对 Telemetry 与 Finding 均为强制要求：

| 字段 | 类型 | 规则 |
|---|---|---|
| `ecs.version` | keyword | 固定为 `9.2.0` |
| `@timestamp` | date | 见 0.4 |
| `event.created` | date | 见 0.4 |
| `event.ingested` | date | 见 0.4 |
| `event.id` | keyword | 见 0.5 |
| `event.kind` | keyword | 见 0.2 |
| `event.dataset` | keyword | 见 0.3 |
| `host.id` | keyword | 必须存在；缺失则按 `sha1(host.name)[:16]` 生成并加前缀 `h-` |
| `host.name` | keyword | 必须存在；缺失则丢弃 |

此外，系统必须写入以下字段用于证据回溯与展示：

| 字段 | 类型 | 规则 |
|---|---|---|
| `event.original` | text | 必须存在；缺失则写入空字符串 |
| `message` | text | 必须存在；缺失则写入空字符串 |

## 2. Telemetry datasets（事实事件）

### 2.1 `hostlog.auth`

用途：登录会话重建与横向移动线索。

必须字段：

| 字段 | 类型 | 规则 |
|---|---|---|
| `event.kind` | keyword | 固定为 `event` |
| `event.dataset` | keyword | 固定为 `hostlog.auth` |
| `event.category[]` | keyword[] | 必须包含 `authentication` |
| `event.type[]` | keyword[] | 取值为 `start` / `end` / `info` |
| `event.action` | keyword | 取值为 `user_login` / `user_logout` / `logon_failed` |
| `event.outcome` | keyword | 取值为 `success` / `failure` |
| `user.name` | keyword | 必须存在 |
| `source.ip` | ip | 必须存在 |
| `session.id` | keyword | 必须存在，生成规则：`sess-` + sha1(host.id + ":" + user.name + ":" + source.ip + ":" + floor(@timestamp/300s))[:16] |

### 2.2 `hostlog.process`

用途：进程树与执行链分析。

必须字段：

| 字段 | 类型 | 规则 |
|---|---|---|
| `event.kind` | keyword | 固定为 `event` |
| `event.dataset` | keyword | 固定为 `hostlog.process` |
| `event.category[]` | keyword[] | 必须包含 `process` |
| `event.type[]` | keyword[] | 取值为 `start` / `end` |
| `event.action` | keyword | 取值为 `process_start` / `process_end` |
| `process.pid` | long | 必须存在 |
| `process.executable` | keyword | 必须存在（绝对路径） |
| `process.entity_id` | keyword | 必须存在；缺失则按 `p-` + sha1(host.id + ":" + pid + ":" + process.start + ":" + process.executable)[:16] 生成，其中 `process.start` 缺失时使用 `@timestamp` |

### 2.3 `hostbehavior.file`

用途：文件访问证据与敏感访问线索。

必须字段：

| 字段 | 类型 | 规则 |
|---|---|---|
| `event.kind` | keyword | 固定为 `event` |
| `event.dataset` | keyword | 固定为 `hostbehavior.file` |
| `event.category[]` | keyword[] | 必须包含 `file` |
| `event.action` | keyword | 取值为 `file_read` / `file_write` / `file_create` / `file_delete` |
| `file.path` | keyword | 必须存在 |
| `process.entity_id` | keyword | 必须存在 |

### 2.4 `netflow.dns`

用途：DNS 行为与基础设施线索。

必须字段：

| 字段 | 类型 | 规则 |
|---|---|---|
| `event.kind` | keyword | 固定为 `event` |
| `event.dataset` | keyword | 固定为 `netflow.dns` |
| `event.category[]` | keyword[] | 必须包含 `network` |
| `event.type[]` | keyword[] | 固定为 `protocol` |
| `event.action` | keyword | 固定为 `dns_query` |
| `network.transport` | keyword | 必须存在 |
| `network.protocol` | keyword | 固定为 `dns` |
| `source.ip` | ip | 必须存在 |
| `destination.ip` | ip | 必须存在 |
| `dns.question.name` | keyword | 必须存在 |

> 其它 `hostbehavior.*` 与 `netflow.*` datasets 的字段口径遵循相同原则：保证可用于实体抽取与证据回溯。具体字段扩展在实现阶段增加时，必须同步更新本文件并与 `52-实体图谱规范.md` 对齐。

## 3. Findings datasets（告警/发现）

### 3.1 Raw Finding（`finding.raw.<provider>`）

必须字段：

| 字段 | 类型 | 规则 |
|---|---|---|
| `event.kind` | keyword | 固定为 `alert` |
| `event.dataset` | keyword | 固定为 `finding.raw.<provider>` |
| `custom.finding.stage` | keyword | 固定为 `raw` |
| `custom.finding.providers[]` | keyword[] | 固定为单元素数组 `[<provider>]` |
| `event.severity` | integer | 取值 0–100 |
| `rule.id` | keyword | 必须存在 |
| `rule.name` | keyword | 必须存在 |
| `threat.framework` | keyword | 固定为 `MITRE ATT&CK` |
| `threat.tactic.id` | keyword | 必须存在；缺失则写 `TA0000` |
| `threat.tactic.name` | keyword | 必须存在；缺失则写 `Unknown` |
| `threat.technique.id` | keyword | 必须存在；缺失则写 `T0000` |
| `threat.technique.name` | keyword | 必须存在；缺失则写 `Unknown` |
| `custom.evidence.event_ids[]` | keyword[] | 必须存在；引用触发该告警的 Telemetry `event.id` |

### 3.2 Canonical Finding（`finding.canonical`）

Canonical Finding 由中心机融合生成，字段必须满足：

| 字段 | 类型 | 规则 |
|---|---|---|
| `event.kind` | keyword | 固定为 `alert` |
| `event.dataset` | keyword | 固定为 `finding.canonical` |
| `custom.finding.stage` | keyword | 固定为 `canonical` |
| `custom.finding.providers[]` | keyword[] | 为多来源去重合并后的数组 |
| `custom.finding.fingerprint` | keyword | 指纹（见 `31-OpenSearch模块规格说明书.md`） |
| `custom.confidence` | float | 取值 0–1 |
| `custom.evidence.event_ids[]` | keyword[] | 合并去重后的证据引用 |

## 4. 示例（用于接口对齐与测试）

### 4.1 `netflow.dns` Telemetry（示例）

```json
{
  "@timestamp": "2026-01-13T12:00:00.000Z",
  "ecs": {"version": "9.2.0"},
  "event": {
    "id": "evt-aaaaaaaaaaaaaaaa",
    "kind": "event",
    "dataset": "netflow.dns",
    "created": "2026-01-13T12:00:00.000Z",
    "ingested": "2026-01-13T12:00:01.000Z",
    "category": ["network"],
    "type": ["protocol"],
    "action": "dns_query",
    "original": "{\"timestamp\":\"...\"}"
  },
  "host": {"id": "h-1111111111111111", "name": "victim-01"},
  "source": {"ip": "10.0.0.10"},
  "destination": {"ip": "8.8.8.8"},
  "network": {"transport": "udp", "protocol": "dns"},
  "dns": {"question": {"name": "example.com"}},
  "message": "DNS query example.com"
}
```

> 说明：示例只用于字段形态对齐；具体字段以本文件前文为准。
