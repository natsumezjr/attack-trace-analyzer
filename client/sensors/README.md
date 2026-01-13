# sensors/

采集层运行与配置说明（部署在客户机侧）。

本项目固定三类数据源：
- Filebeat(+Sigma)：主机系统日志（hostlog.*）+ 基于 Sigma 规则的异常检测（finding.*）
- Falco：主机行为告警（hostbehavior.*）
- Suricata：网络流量与告警（netflow.* + alert）

这些采集器的**原始输出**最终会被 `client/backend/` 读取并归一化为 ECS 子集。

## 一键部署（Docker Compose）

`client/sensors/docker-compose.yml` 已统一编排 Falco / Suricata / Filebeat，并写入同一个
SQLite 文件 `./data/sqlite/data.db`，不同数据源分别写入独立表：

- falco → 表 `falco`
- suricata → 表 `suricata`
- filebeat → 表 `filebeat`

`client/sensors/docker-compose.yml` 还包含 go-client（读取同一份 `data.db`，端口 `8888`）。
