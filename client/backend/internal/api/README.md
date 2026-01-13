# api/

HTTP API 层（由中心机调用）。

接口口径必须严格对齐：
- `docs/06C-客户端中心机接口规范.md`

v1 预期包含：
- `GET /api/v1/health`
- `POST /api/v1/pull`（Bearer token + cursor/limit/want）

