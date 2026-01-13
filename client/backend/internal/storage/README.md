# storage/

本地缓冲存储层（SQLite）。

v1 关键约束（来自 `docs/06C-客户端中心机接口规范.md`）：
- `cursor = SQLite 自增 id`（中心机用 cursor 拉取）
- `limit` 默认 500，客户端可做上限保护
- 支持按 `want.event_kinds` / `want.datasets` 做过滤

建议实现形态（后续落代码时再细化）：
- 一张“事件表”（自增 id + json blob + 索引字段）
- 或分 Telemetry/Findings 两张表（权衡后决定）

