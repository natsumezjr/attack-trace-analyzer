# sensors/falco

Falco 的部署与输出约定（v1）。

你已确认：靶机 Linux 且允许高权限，因此推荐 **Docker（privileged）+ host network** 快速落地。

后续需要明确：
- 规则集：MVP 优先使用高价值规则命中（不要全量 syscall 入库）

## 推荐输出（给客户端后端消费）

v1 推荐把 Falco 输出为 JSON 并落盘为文件，客户端后端直接 tail/读取：

- `events.json`：例如 `client/deploy/compose/data/falco/events.json`

对应模板配置在：
- `client/deploy/compose/falco/falco.yaml`
