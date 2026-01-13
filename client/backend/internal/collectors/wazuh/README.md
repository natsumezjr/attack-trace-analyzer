# collectors/wazuh

Wazuh 采集适配（主机日志）。

目标输出：
- Telemetry：`hostlog.*`（如 `hostlog.auth` / `hostlog.process` / `hostlog.file_registry`）
- Findings：若 Wazuh 侧产告警，映射到 `event.kind=alert` 与 `event.dataset=finding.raw`

字段口径：
- `docs/06A-ECS字段规范.md`（hostlog.* / finding.*）

注意：Wazuh 的部署形态（agent/manager/API/log 文件）需要结合靶场决定，后续在 `client/sensors/wazuh/` 明确。

