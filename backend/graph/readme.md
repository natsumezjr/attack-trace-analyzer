## ECS -> Neo4j Graph

### 简介

将 ECS 事件转换为 Neo4j 实体关系图（Host/User/Process/File/IP/Domain/NetConn），用于告警回溯和路径分析。

### 关系类型

- `LOGON`：User -> Host（登录）
- `PARENT_OF`：Process -> Process（父子）
- `USES`：Process -> File（使用/访问）
- `OWNS`：Host/Process -> IP/NetConn（拥有/归属）
- `CONNECTED`：NetConn -> NetConn（仅连接语义）
- `RESOLVED`：Host -> Domain（发起解析）
- `RESOLVES_TO`：Domain -> IP（解析结果）

### Docker（Neo4j + OpenSearch）

**注意**：Neo4j 的 docker-compose.yml 已合并到 `backend/opensearch/docker-compose.yml`。

```bash
# 从 opensearch 目录启动（包含 OpenSearch + Neo4j）
cd backend/opensearch
docker compose up -d     # 创建
docker compose down -v   # 删除

# 或者从项目根目录启动
docker compose -f backend/opensearch/docker-compose.yml up -d
```

默认地址：
- **OpenSearch**: `https://localhost:9200`
- **Neo4j Browser**: `http://localhost:7474`
- **Neo4j Bolt**: `bolt://localhost:7687`

默认账号：
- **OpenSearch**: `admin` / `OpenSearch@2024!Dev`
- **Neo4j**: `neo4j` / `password`

### 运行方式

1) 使用 OpenSearch 拉取 ECS 并导入 Neo4j（默认）
```bash
python backend/graph/load.py
```

2) 使用本地样例 `testExample.json` 导入
```bash
python backend/graph/load.py --file
```

3) 模块测试（基于 `testExample.json`）
```bash
python backend/graph/test.py
```

### 环境变量

Neo4j：
- `NEO4J_URI`（默认 `bolt://localhost:7687`）
- `NEO4J_USER`（默认 `neo4j`）
- `NEO4J_PASSWORD`（默认 `password`）
- `NEO4J_DATABASE`（可选）

OpenSearch（使用 `load.py` 默认分支时需要）：
- `OPENSEARCH_NODE`（例如 `https://localhost:9200`）
- `OPENSEARCH_USERNAME`
- `OPENSEARCH_PASSWORD`

### 文件说明

- `ecs_ingest.py`：ECS 事件 -> 图节点/边映射
- `api.py`：Neo4j 读写与批量导入
- `load.py`：导入入口（OpenSearch / 文件）
- `test.py`：样例测试入口
