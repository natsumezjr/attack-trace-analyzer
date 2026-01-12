# deploy/

客户端侧部署文件入口。

预期会同时支持两种形态（按靶场实际选择）：
- `compose/`：docker compose 一键拉起（推荐，易复制到 5 节点）
- `systemd/`：宿主机直接跑二进制 + systemd 管理（备选）

