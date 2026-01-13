# collectors/filebeat

Filebeat 采集适配（主机系统日志 + Sigma 规则告警）。

v1 约定：
- 输入为 **ECS 格式的 ndjson**（每行一个 JSON object），通常来自 Filebeat 输出或 Filebeat+Sigma 检测器输出。
- 若输入缺少必要字段，本模块会做最小补齐（`ecs.version` / `event.*` / `host.*` / `agent.*`）。

输出：
- Telemetry：`event.kind=event`，`event.dataset=hostlog.*`
- Findings：`event.kind=alert`，`event.dataset=finding.raw`

字段口径：
- `docs/06A-ECS字段规范.md`（hostlog.* / finding.*）

