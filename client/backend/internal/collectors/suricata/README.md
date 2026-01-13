# collectors/suricata

Suricata 采集适配（网络流量 + 告警）。

建议 v1 重点：
- 解析 EVE JSON：
  - flow/dns/http/tls… → `event.kind=event`，`event.dataset=netflow.*`
  - alert → `event.kind=alert`，`event.dataset=finding.raw`（或按约定落到 finding.*）

字段口径：
- `docs/06A-ECS字段规范.md`（netflow.* / finding.*）

