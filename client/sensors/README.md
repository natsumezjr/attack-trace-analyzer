# sensors/

采集层运行与配置说明（部署在客户机侧）。

本项目固定三类数据源：
- Wazuh：主机日志（hostlog.*）
- Falco：主机行为告警（hostbehavior.*）
- Suricata：网络流量与告警（netflow.* + alert）

这些采集器的**原始输出**最终会被 `client/backend/` 读取并归一化为 ECS 子集。

