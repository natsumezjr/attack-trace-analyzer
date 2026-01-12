# client-backend

客户端后端主程序入口（未来放置 `main.go`）。

建议职责边界：
- 仅做启动编排：读取配置、初始化依赖、启动 HTTP Server、启动采集协程、启动注册/续期逻辑
- 业务逻辑放在 `client/backend/internal/...`

