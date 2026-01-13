# deploy/compose

本目录提供**每台客户机一份**的 `docker-compose.yml`，用于编排采集层（Falco/Suricata）以及后续的客户端后端（Go + SQLite）。

> 适用环境：**Linux 靶机**（Falco/Suricata 通常需要 `privileged` 与 host network；Docker Desktop/macOS 不适用）。

## 当前包含

- `docker-compose.yml`：传感器编排（已包含 Falco/Suricata）；`client-backend` 先留占位（等你开始写 Go 再启用）
- `.env.example`：每台机器需要复制一份并改成自己的 `client_id/host/center` 配置
- `falco/`：Falco 配置模板（JSON 输出 → 文件）
- `suricata/`：Suricata 规则（`local.rules`），EVE JSON 由镜像内默认配置输出为 `eve.json`

## 快速使用（每台客户机）

1) 进入目录并准备环境变量：

```bash
cd client/deploy/compose
cp .env.example .env
```

2) 编辑 `.env`（至少改这几项）：

- `CLIENT_ID`（稳定不变）
- `HOST_ID` / `HOST_NAME`
- `CENTER_BASE_URL`（中心机地址）
- `CLIENT_LISTEN_URL`（中心机能访问到的本机地址）
- `SURICATA_INTERFACE`（网卡名，如 `eth0/ens33/enp0s3`）
- `WAZUH_ALERTS_JSON`（Wazuh JSON 文件路径，默认 `/var/ossec/logs/alerts/alerts.json`）

3) 一键拉起（采集器 + 客户端后端）：

```bash
docker compose up -d --build
```

4) 观察输出（v1 最重要的是“文件能落出来”）：

- Suricata：`./data/suricata/eve.json`
- Falco：`./data/falco/events.json`
- Client Backend：监听 `CLIENT_BIND_ADDR`（默认 `0.0.0.0:18080`），提供 `/api/v1/health`

> 说明：客户端后端（Go）后续会把这些原始输出读进来，统一映射为 ECS 子集并写入 SQLite，再由中心机轮询 `/pull` 拉取。

## 参考（官方/上游文档）

- Falco 容器部署：`https://falco.org/docs/setup/container/`
- Suricata 容器能力（capabilities）建议：`https://docs.suricata.io/en/suricata-8.0.1/security.html#containers`
- Suricata CLI 规则加载（`-s/-S`）：`https://docs.suricata.io/en/suricata-8.0.1/command-line-options.html`
