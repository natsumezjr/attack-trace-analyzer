# normalize/

归一化层：将 collectors 输出的 Raw 事件映射为 **ECS 子集**。

规范来源（必须遵守）：
- `docs/06A-ECS字段规范.md`

建议拆分：
- `ecs/`：ECS 公共字段填充、dataset 映射、ID 生成策略等
- 针对每类数据源的 mapping（hostlog/hostbehavior/netflow/finding）

