# sensors/wazuh

Wazuh 的部署与输出约定（v1）。

你已确认：**每台客户机本地就能拿到可消费的 Wazuh JSON**。因此 v1 推荐最简单的接入方式是：客户端后端直接读取本机落盘的 JSON 文件。

后续需要明确：
- Wazuh 原始事件如何映射到 `hostlog.*` 与 `finding.*`（字段口径见 ECS 文档）

接口与字段规范参考：
- `docs/06C-客户端中心机接口规范.md`
- `docs/06A-ECS字段规范.md`

## 建议的“可消费 JSON”文件（默认约定）

常见路径（Wazuh 安装默认目录）：

- `alerts.json`：`/var/ossec/logs/alerts/alerts.json`

`alerts.json` 的优势是：
- 直接就是“告警/发现”类信号（适合作为 Finding）
- 数据量比全量日志更可控，更适合 3 天窗口

> 如果你们后续需要更“全”的主机日志 Telemetry，可以再补充读取 Wazuh 的 archive/原始日志文件（这属于 v1 以后的增强点）。

