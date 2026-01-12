# Attack Trace Analyzer（恶意攻击行为溯源分析系统）

> 课程设计题目：**基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现**

本仓库以“文档先行”为核心方法：先把**需求 → 规格 → 字段 → 接口 → 存储/图谱 → 选型口径**写死，再并行实现各模块，保证 3 天开发窗口内不走弯路。

---

## 30 秒读懂本项目

**目标**：把多源采集到的事件统一为 ECS 子集，并在中心机侧完成检索、检测、关联、攻击链重建与可视化展示。

**端到端数据流**：

```
Wazuh / Falco / Suricata（采集）
  → Client Backend（Go：ECS 归一化 + SQLite 缓冲 + /health + /pull）
  → Center（Next.js：注册表 + 轮询拉取）
  → OpenSearch（Telemetry / Findings / Chains）
  → Python 算法模块（告警融合 / 时间窗关联 / 路径重建）
  → Neo4j（实体关系图）
  → Next.js UI（时间线 / 图 / 报告导出）
```

---

## 文档入口（唯一真相来源）

- `docs/00-文档索引.md`：建议从这里开始，按顺序读
- `docs/06C-客户端中心机接口规范.md`：客户端 ↔ 中心机接口（注册 / 拉取 / 健康检查）
- `docs/05-模块与数据流说明.md`：面向组员快速上手的"故事线"

---

## 代码结构（当前仓库）

> 说明：代码与文档会同步迭代；当二者冲突时，以 `docs/` 下的规格文档为准（接口以 `docs/06C-客户端中心机接口规范.md` 为主）。

| 目录 | 作用 |
|---|---|
| `server/` | **中心机 Next.js 全栈**（页面 + API，承载注册表/轮询器/展示） |
| `analyzer/` | 关联/溯源相关的 **Python 模型与算法**（逐步落地） |
| `graph/` | 图谱相关的 Python 试验代码与数据样例 |
| `docs/` | 全部可交付文档（需求/规格/字段/接口/存储/调研/选型） |

---

## 快速运行（中心机 UI）

> UI 开发与页面联调在 `server/` 下进行。

```bash
cd server
npm ci
npm run dev
```

浏览器打开：`http://localhost:3000`

---

## 客户端 ↔ 中心机接口（v1 摘要）

接口详情以 `docs/06C-客户端中心机接口规范.md` 为准；这里给一个"看一眼就能写代码"的摘要。

| 方向 | 接口 | 方法 | 说明 |
|---|---|---|---|
| Client → Center | `/api/v1/clients/register` | `POST` | 客户端启动注册，拿到 `client_token` 与轮询间隔 |
| Center → Client | `/api/v1/health` | `GET` | **v1 必做**：健康检查（在线探测/排障） |
| Center → Client | `/api/v1/pull` | `POST` | 核心拉取接口：SQLite cursor + `want.*` 过滤 |

**已拍板的实现口径**：
- Client Backend：Go；本地缓冲 **SQLite**；`cursor=SQLite 自增 id`；传输使用 **HTTP**（靶场内网）
- Center：注册表落 **OpenSearch**（建议索引 `client-registry-*`）；轮询参数固定；离线仅做状态展示不做对外通知
- 算法模块：Python
