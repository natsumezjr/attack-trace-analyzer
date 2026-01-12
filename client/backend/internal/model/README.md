# model/

数据模型（ECS 子集 + 必要的内部类型）。

说明：
- ECS 字段口径以 `docs/06A-ECS字段规范.md` 为准
- `custom.*` 命名空间用于所有自定义字段

建议这里放：
- ECS 事件结构体（Telemetry / Finding）
- `want` 过滤结构（pull request）
- 错误响应结构（pull error response）

