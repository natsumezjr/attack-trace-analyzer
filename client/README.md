# 客户端（采集层 + 客户端后端）代码区

本目录用于存放**部署在靶场各节点（客户机/被监控主机）**上的所有代码与部署文件，覆盖：

- **采集层（Sensors）**：Filebeat(+Sigma) / Falco / Suricata
- **客户端后端（Client Backend）**：Go + SQLite，本地缓冲 + ECS 归一化 + 注册 + `/health` + `/pull`

> 口径以仓库 `docs/` 为准（文档先行）。

## 目录结构（约定）

- `backend/`：客户端后端（Go 服务，SQLite 缓冲，提供 HTTP API）
- `sensors/`：采集器运行/配置说明（Filebeat/Falco/Suricata）
- `deploy/`：部署形态（docker compose / systemd 等）
- `examples/`：样例数据（raw / ecs），用于联调与测试

## 与中心机的接口（v1）

接口规范见：
- `docs/06C-客户端中心机接口规范.md`

重点约束（实现时不要偏离）：
- 客户端启动后 `POST /api/v1/clients/register`
- 中心机轮询 `GET /api/v1/health` 与 `POST /api/v1/pull`
- `cursor = SQLite 自增 id`（项目已拍板）
- 中心机拉取必须携带 `Authorization: Bearer <client_token>`

## 归一化字段（ECS 子集）

字段规范见：
- `docs/06A-ECS字段规范.md`

核心要求：
- `ecs.version = 9.2.0`
- `event.kind ∈ {event, alert}`
- `event.dataset` 统一为：`hostlog.*` / `hostbehavior.*` / `netflow.*` / `finding.*`
- 自定义字段统一放入 `custom.*`

## 部署建议（MVP）

推荐把**客户端后端 +（尽可能）采集器**一起用 `docker compose` 编排在每台客户机上，便于 5 节点靶场快速复制部署。

注意：
- Falco / Suricata 容器化通常需要 `--privileged`、挂载宿主机目录、以及 host 网络/抓包权限（需在 `deploy/` 中细化）
- Filebeat 生态相对轻：适合做“主机系统日志采集”，并可结合 Sigma 规则进行异常检测（见 `sensors/filebeat/`）
