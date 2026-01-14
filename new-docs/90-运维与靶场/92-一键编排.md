# 一键部署编排（center + 4×client + c2）

目标：让你在 `10.92.35.13` 这台主机上，用 Docker Compose 管理整套靶场，并能做到：

- 一键启动/停止
- 一键清空数据
- 多个 client 实例互不冲突（端口/数据目录隔离）
- c2-01 提供 DNS+HTTP 且尽量能被 Suricata 在 `ens5f1` 上观测到

> 说明：本仓库现状是“中心机基础设施已容器化、后端/前端默认跑宿主、client 已容器化”。你作为靶场负责人，先把“容器与网络底座”编排好即可；后端/前端是否也容器化可以后续再做。

---

## 0. 先做一次“统一约定”

### 0.1 物理网卡

你的内网网卡为：`ens5f1`（你已抓包验证）

### 0.2 C2 独立 IP（推荐）

建议分配：`10.92.35.50`（确保未被占用）

---

## 1. 你需要准备的 Compose 组织方式（推荐结构）

### 结构 A（推荐，最清晰）：3 份 compose

- `backend/docker-compose.yml`：OpenSearch + Neo4j（仓库已有）
- `client/docker-compose.yml`：单个客户机采集栈（仓库已有）
- 你新增一份“靶场编排用 compose”（建议放在宿主某个 run 目录）
  - 用它来统一启动：c2-01 + 4×client（以及可选的 center 后端/前端）

> 你说“中心机和客户机没有完全写好”，此时最重要的是把“多实例启动逻辑”固定下来。等开发补齐接口后，你只需要换镜像/更新代码，不需要重做拓扑。

---

## 2. client 多实例怎么启动（关键点）

client 的 compose 默认端口是 `8888` 和 `8080`，多实例会冲突。你需要给每个实例：

- 不同宿主端口（见 `01` 的表）
- 不同 `HOST_ID/HOST_NAME`
- 不同 `./data` 挂载目录（否则输出文件混在一起）

你可以选两种方式：

### 方式 2.1：复制 4 份 client 目录（最稳、最直观）

- `run/client-01/` 放一份 `client/` 文件树（只要 compose 和 data 目录在）
- 各目录里的 `docker-compose.yml` 改端口映射与环境变量

优点：最少 compose 高级技巧；排障最简单  
缺点：目录重复

### 方式 2.2：同一份 compose，用不同工作目录 + 不同 project name（更工程化）

核心要点：

- 在 `run/client-01/` 目录里执行 `docker-compose -p client01 -f <repo>/client/docker-compose.yml up -d`
- 因为执行目录不同，compose 里相对路径 `./data` 会落到不同实例目录

优点：不复制代码  
缺点：对“在哪个目录执行”更敏感，容易新手踩坑

---

## 3. c2-01（DNS+HTTP）怎么纳入统一编排

建议先按这个顺序推进：

1) 先把 c2-01 独立跑通（DNS 可解析 + HTTP 可访问）  
2) 再把 client 的“DNS/HTTP 请求”指向 `c2.lab.local`（让 Suricata 有稳定证据）  
3) 最后再考虑把 c2 合并进“总 compose”

c2 的细节见：

- `03-c2-01-DNS+HTTP（macvlan优先）.md`

---

## 4. 一键清空数据（你必须提供给组内/老师）

你需要能在演示前做到：

- 停止所有容器
- 清空 `run/client-*/data/`（至少清空 suricata/falco/filebeat 输出）
- 重置 RabbitMQ 队列（最简单做法：重建 rabbitmq 容器；若多实例则每个实例各自重建）
- （可选）清空 OpenSearch/Neo4j 持久化卷（演示前“从零开始”时很有用）

建议你把“清空策略”分两档：

- **轻量清空**：只清 client 数据（重新产生采集证据）
- **全量清空**：连同 OpenSearch/Neo4j 卷一起清（从零开始演示整条流水线）

---

## 5. 你下一步实际要做的事情（按优先级）

1) 先只跑 `backend/docker-compose.yml`（OpenSearch+Neo4j）确认端口可用  
2) 再跑 1 个 client 实例确认 RabbitMQ 队列有消息（或拉取接口返回 `total>0`）  
3) 再加 c2-01（先独立跑通 DNS+HTTP）  
4) 最后扩到 4 个 client 实例（满足 ≥5 节点）

验证标准见：

- `04-验证清单（网络-采集-证据）.md`
