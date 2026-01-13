# collectors/

采集适配层：把不同传感器的原始输出转换为“可归一化的 Raw 事件”。

原则：
- 每个采集器单独一个子目录（filebeat/falco/suricata）
- 采集层尽量只关心“怎么拿到事件”，不掺杂 ECS 字段映射逻辑
- Raw → ECS 的映射放在 `internal/normalize/`
