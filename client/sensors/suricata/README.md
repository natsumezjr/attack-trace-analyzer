# sensors/suricata

Suricata 的部署与输出约定（v1）。

你已确认：靶机 Linux 且允许高权限，因此推荐 **Docker（privileged）+ host network** 在每台客户机落地。

后续需要明确：
- EVE JSON 的启用与输出路径
- 抓包接口/网卡选择（靶场内网环境）
- 哪些协议事件纳入 v1（flow/dns/http/tls…）

## 推荐输出（给客户端后端消费）

v1 推荐只要保证 EVE JSON 落盘即可，客户端后端直接读取：

- `eve.json`：例如 `client/deploy/compose/data/suricata/eve.json`

模板配置在：
- `client/deploy/compose/suricata/suricata.yaml`

