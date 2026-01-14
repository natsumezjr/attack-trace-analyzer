# Attack Trace Analyzer（恶意攻击行为溯源分析系统）

> 课程设计题目：基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现

本仓库采用“文档先行”：先把要求、需求、规格、数据规范与接口规范写清楚，再实现代码。

## 文档导航

本仓库的正式文档体系统一在 `new-docs/`：

- 总览入口：`new-docs/README.md`
- 文档索引：`new-docs/00-总览/00-文档索引.md`
- 交付打包：`new-docs/10-交付与答辩/11-交付物清单与打包结构.md`
- 一键启动：`new-docs/90-运维与靶场/92-一键编排.md`
- 验收与复现：`new-docs/20-需求与验收/21-验收标准与验收用例.md`、`new-docs/20-需求与验收/22-攻击场景与复现剧本.md`

## 系统概览（中心机侧关键机制）

中心机以“单定时器一条龙”方式运行，每次 tick 严格顺序执行：

1) 定时从客户机拉取新数据（带游标）  
2) 定时写入 OpenSearch（字段处理与幂等去重）  
3) 定时触发 Store-first 检测 + Raw Findings 融合生成 Canonical Findings，写回 OpenSearch  
4) 定时触发（Canonical + 补充 Telemetry）ECS → Graph，写入 Neo4j  

老师在前端可视化时：前端请求后端，后端通过 Neo4j 查询返回图结构并渲染。老师点选节点触发溯源任务时：后端创建异步任务并返回 `task_id`，Analysis 模块完成计算后把结果写回 Neo4j 边属性，前端轮询任务状态并展示结果。

## 快速开始

### 前置

- Docker & Docker Compose
- Node.js 18+（前端）
- Python 3.12+
- uv

### 启动中心机（OpenSearch + Neo4j + FastAPI + 前端）

启动依赖服务：

```bash
cd backend
docker compose up -d
```

启动后端：

```bash
cd backend
export OPENSEARCH_NODE="https://localhost:9200"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="OpenSearch@2024!Dev"
export OPENSEARCH_URL="https://localhost:9200"
export OPENSEARCH_USER="admin"
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="password"
uv sync
uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

启动前端：

```bash
cd frontend
npm ci
npm run dev
```

访问：

- 前端：`http://localhost:3000`
- 后端健康检查：`http://localhost:8000/health`
- Neo4j Browser：`http://localhost:7474`
- OpenSearch：`https://localhost:9200`

### 启动客户机（Linux 节点）

客户机侧 `docker-compose` 需要特权能力（Falco/Suricata），目标运行环境为 Linux 主机。

```bash
cd client
cp .env.example .env
docker compose up -d --build
```

客户机与中心机的完整部署方式、环境变量与靶场网络规划见：`new-docs/80-规范/89-环境变量与配置规范.md`、`new-docs/90-运维与靶场/`。

## 目录结构

| 目录 | 技术栈 | 作用 |
|---|---|---|
| `client/` | Docker + RabbitMQ + Go | 客户机侧采集/转换/缓冲与对外拉取接口 |
| `backend/` | Python FastAPI + uv | 中心机后端：流水线调度、OpenSearch/Neo4j/Analysis 模块与 API |
| `frontend/` | Next.js + TypeScript | 中心机前端：可视化与报告导出 |
| `new-docs/` | Markdown | 课程交付文档体系（唯一正式文档） |

## 测试

后端测试：

```bash
cd backend
RUN_NEO4J_TESTS=0 uv run pytest -q
RUN_OPENSEARCH_TESTS=1 RUN_NEO4J_TESTS=1 KEEP_NEO4J_TEST_DATA=0 uv run pytest -q
```
