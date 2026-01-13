# config/

配置加载与校验。

建议配置项（后续实现时落实）：
- 中心机地址（register URL）
- 客户端对外 listen 地址/端口（listen_url）
- client_id / host.id / host.name（或自动生成并落盘）
- 各采集器输入（socket/file/http endpoint 等）
- SQLite 路径、容量/保留策略

