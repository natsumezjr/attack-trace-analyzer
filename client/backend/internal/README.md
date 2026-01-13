# internal/

客户端后端内部实现（不对外暴露的 Go package）。

建议按“职责模块”拆分，避免后期文件堆成一团：
- `api/`：HTTP API（health/pull）
- `collectors/`：采集适配（filebeat/falco/suricata）
- `normalize/`：Raw → ECS 子集映射
- `storage/`：SQLite 缓冲与游标读取
- `registry/`：向中心机注册、维护 token
- `config/`：配置加载与校验
- `model/`：ECS 子集结构体与公共类型
