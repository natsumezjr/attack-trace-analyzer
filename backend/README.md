# Backend（中心机后端 / FastAPI）

本目录是 **中心机后端**（Python + FastAPI），包含：

- `app/`：后端主代码（API、services、schemas、core）
- `docker-compose.yml`：后端依赖服务（OpenSearch + Neo4j）
- `.env.example`：Docker Compose 变量模板（可选复制为 `.env` 覆盖默认值）
- `tests/`：后端测试（pytest）

> **规格/设计文档以 `docs/` 为准**（当文档与代码冲突时优先看 `docs/`）：
>
> - 环境变量：`docs/ENV_CONFIG.md`
> - 存储路由/索引：`docs/06-数据库设计.md`
> - 图谱模型：`docs/06B-存储与图谱设计.md`
> - 客户端接口：`docs/06C-客户端中心机接口规范.md`

---

## 快速开始

### 1）启动 OpenSearch + Neo4j

```bash
cd backend
cp .env.example .env  # 可选：覆盖默认配置
docker compose up -d
```

默认端口：
- OpenSearch：`https://localhost:9200`（开发环境通常是自签名证书，`curl` 需加 `-k`）
- Neo4j Browser：`http://localhost:7474`
- Neo4j Bolt：`bolt://localhost:7687`

### 2）安装 Python 依赖

```bash
cd backend
uv sync
```

### 3）启动 FastAPI

```bash
cd backend
uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## 环境变量

统一说明见 `docs/ENV_CONFIG.md`。

几点补充：
- `backend/.env` **主要给 Docker Compose 做变量替换**；Python 代码默认使用 `os.getenv(..., default)`，不会自动读取 `.env` 文件（除非你在入口处自行引入 `python-dotenv`）。
- OpenSearch 默认是 HTTPS（`backend/app/services/opensearch/client.py` 会根据 `OPENSEARCH_NODE` 的 scheme 自动判断 `use_ssl`）。

---

## 运行测试（pytest）

```bash
cd backend
uv run pytest
```

部分测试依赖外部服务，默认会跳过；需要显式开启：

```bash
# 需要 OpenSearch 的测试
RUN_OPENSEARCH_TESTS=1 uv run pytest

# 需要 Neo4j 的测试
RUN_NEO4J_TESTS=1 uv run pytest
```

---

## OpenSearch 模块（`app/services/opensearch/`）

代码位置：`backend/app/services/opensearch/`

常用入口（对外 API）建议从包导入：
- `initialize_indices()`：创建/初始化索引
- `store_events()`：入库（按 `event.kind` + `event.dataset` 路由）
- `run_data_analysis()`：检测 + 去重（可选依赖 Security Analytics）

### Sigma 规则库（Submodule）

Sigma 规则库目录：`backend/app/services/opensearch/sigma-rules/`

```bash
git submodule update --init --recursive
```

### 脚本工具

辅助脚本目录：`backend/scripts/`
- `fetch_mitre_attack_cti.sh`：下载 MITRE ATT&CK CTI 数据
- `opensearch/`：OpenSearch 相关测试和工具脚本
  - `clear_findings_data.py`：清除 findings 数据
  - `generate_security_test_events.py`：生成测试事件
  - `test_security_analytics_flow.py`：完整测试流程
  - 其他测试工具（详见 `backend/scripts/README.md`）

Sigma 规则和 Security Analytics 配置脚本仍在 `app/services/opensearch/` 目录：
- `import_sigma_rules.py`：导入 Sigma 规则
- `setup_security_analytics.py`：配置 Security Analytics detector

---

## 图谱模块（`app/services/graph/`）

代码位置：`backend/app/services/graph/`

本模块将 ECS 事件写入 Neo4j（实体/关系）。

### 关系类型（当前代码实现）

当前代码中的关系类型定义在 `backend/app/services/graph/models.py`：
- `LOGON`：User → Host
- `PARENT_OF`：Process → Process
- `USES`：Process → File
- `OWNS`：Host/Process → IP/NetConn
- `CONNECTED`：NetConn → NetConn
- `RESOLVED`：Host → Domain
- `RESOLVES_TO`：Domain → IP

> 备注：`docs/06B-存储与图谱设计.md` 的关系命名（如 `SPAWNED`/`ACCESSED`）与当前实现存在差异；需要统一口径时，请以 `docs/` 为基准再决定是否调整代码。

### 快速导入（样例数据）

样例文件：`backend/tests/fixtures/graph/testExample.json`

```bash
cd backend
uv run python -m app.services.graph.load --file
```

---

## TTP Similarity（离线 ATT&CK CTI）

默认路径：`backend/app/services/ttp_similarity/cti/enterprise-attack.json`

数据文件较大，默认不提交到 Git；可执行：

```bash
cd backend
./scripts/fetch_mitre_attack_cti.sh
```

