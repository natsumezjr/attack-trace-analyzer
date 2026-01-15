# 靶场交付说明（SSH / 端口 / 拓扑）

适用对象：组内同学/老师/验收人员。本文只讲**怎么连上靶场、有哪些服务、端口怎么用**。

---

## 1. 登录服务器（SSH）

- **服务器 IP**：`10.92.35.13`
- **登录命令**（示例）：

```bash
ssh ubuntu@10.92.35.13
```
密码：#EDCvfr4%TGB10（注意尽量只在~/attack-trace-analyzer下活动）
> 若你们有跳板机/非 22 端口/密钥登录，请把实际参数替换到上面命令中（例如 `-p <port>`、`-i <key>`）。

---

## 2. 靶场逻辑拓扑（≥5 节点）

- **center-01（中心机）**：OpenSearch + Neo4j（可选：后端/前端）
- **client-01..04（客户机）**：Falco / Filebeat / Suricata → SQLite → Client API
- **c2-01（C2）**：DNS + HTTP（macvlan 独立 IP，便于网络可观测）

---

## 3. 服务与端口一览（验收口径）

### 3.1 center-01（中心机）

- **OpenSearch**：`https://10.92.35.13:9200`（自签名，curl 建议加 `-k`）
- **Neo4j Browser**：`http://10.92.35.13:7474`
- **Neo4j Bolt**：`10.92.35.13:7687`

（如果你们额外跑了后端/前端）
- 后端：`http://10.92.35.13:8000`
- 前端：`http://10.92.35.13:3000`

### 3.2 client-01..04（客户机 API）

每个 client 对外提供 3 个接口（返回 SQLite 全表，便于验收）：

- `GET /filebeat`
- `GET /falco`
- `GET /suricata`

端口规划：

- **client-01**：`http://10.92.35.13:18881/*`
- **client-02**：`http://10.92.35.13:18882/*`
- **client-03**：`http://10.92.35.13:18883/*`
- **client-04**：`http://10.92.35.13:18884/*`

（可选）Suricata exporter：
- client-01..04：`18081..18084`（对应各自实例）

### 3.3 c2-01（C2：DNS + HTTP）

- **DNS（CoreDNS）**：`10.92.35.50:53/udp` + `10.92.35.50:53/tcp`
- **HTTP（Nginx）**：`http://10.92.35.51:80`
- **域名解析**：`c2.lab.local -> 10.92.35.51`

> 抓包验收建议在宿主机 `macvlan0` 上进行（而不是 `ens5f1`）。

---

## 4. 目录与数据位置（给开发/排障用）

以你们默认落地路径为准：

- 代码：`$BASE/repo/attack-trace-analyzer/`
- 运行目录：`$BASE/run/`
  - `client-01..04/data/`：SQLite（`filebeat.db / falco.db / suricata.db` 等）
  - `c2/`：CoreDNS 配置与 Nginx 静态文件

