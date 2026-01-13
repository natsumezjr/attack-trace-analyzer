# collectors/falco

Falco 采集适配（主机行为告警为主）。

建议 v1 重点：
- Falco 规则命中事件作为高价值信号 → `event.kind=alert`
- dataset 归入：`hostbehavior.*`（Telemetry）或 `finding.raw`（Finding），由后续实现细化

字段口径：
- `docs/06A-ECS字段规范.md`（hostbehavior.* / finding.*）

