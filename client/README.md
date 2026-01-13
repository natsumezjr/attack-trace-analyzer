# client/（客户机侧部署包）

本目录是“客户机侧”一键部署入口：**3 个传感器 + 1 个 Go 后端**，最终以共享 SQLite `data.db` 为数据交换与持久化介质。

## 目录结构（最终约定）

- `docker-compose.yml`：一键部署入口（Linux 客户机）
- `.env.example`：环境变量模板（复制为 `.env` 后修改）
- `backend/`：唯一 Go 后端（从 SQLite 读取数据并提供 HTTP API）
- `sensor/`：三类传感器（不包含 Go）
  - `falco/`：主机行为告警（写入 `falco` 表）
  - `suricata/`：网络流量/告警（写入 `suricata` 表）
  - `filebeat/`：主机日志 + Sigma 检测（写入 `filebeat` 表）
- `data/`：运行时数据目录（会生成 `data.db`；不应提交到 git）

## 数据流（已拍板）

1) Sensors 侧写入共享 SQLite：`./data/data.db`

- Falco → `falco-ecs` 转换 → 表 `falco`
- Suricata → `suricata-exporter` 转换 → 表 `suricata`
- Filebeat(+Sigma) → detector 写库 → 表 `filebeat`

2) Backend 侧只做读取与对外查询（完全按照 sqlite-api 逻辑）：

- 读取：`/data/data.db`
- 提供接口：`GET /falco`、`GET /suricata`、`GET /filebeat`

> 本仓库当前 **不提供任何兼容层**：没有 `/api/v1/pull`、没有注册、没有 token 鉴权；只保留上述 3 个查询接口。

## 一键启动

```bash
cd client
cp .env.example .env
docker compose up -d --build
```

## Backend API

默认端口：`8888`。

- `GET http://<client-ip>:8888/falco`
- `GET http://<client-ip>:8888/suricata`
- `GET http://<client-ip>:8888/filebeat`

响应格式（示例）：

```json
{"total":123,"data":[{"id":1,"event_json":"{...}"}]}
```
