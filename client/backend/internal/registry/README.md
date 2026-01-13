# registry/

客户端注册中心机逻辑。

接口口径：
- `POST /api/v1/clients/register`（见 `docs/06C-客户端中心机接口规范.md`）

职责建议：
- 启动时注册，获取 `client_token` 与 `poll_interval_seconds`
- 本地持久化 `client_id`（避免重启变更）
- 注意：token 不得在日志中明文打印

