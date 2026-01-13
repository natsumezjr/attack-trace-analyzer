# collectors/wazuh（Deprecated）

⚠️ 本项目已不再使用 Wazuh 作为主机日志采集来源：主机系统日志采集改为 **Filebeat**，并结合 **Sigma 规则**进行异常检测（见 `client/sensors/filebeat/`）。

本目录仅作为历史实现参考保留。

目标输出：
- Telemetry：`hostlog.*`（如 `hostlog.auth` / `hostlog.process` / `hostlog.file_registry`）
- Findings：若 Wazuh 侧产告警，映射到 `event.kind=alert` 与 `event.dataset=finding.raw`

字段口径：
- `docs/06A-ECS字段规范.md`（hostlog.* / finding.*）
