# 环境变量配置说明

## 概述

本项目使用统一的 `.env` 文件管理所有环境变量，包括：
- OpenSearch 配置
- Neo4j 配置
- Backend 应用配置
- Docker Compose 服务配置

## 快速开始

1. **复制环境变量模板**：
   ```bash
   cp .env.example .env
   ```

2. **编辑 `.env` 文件**，根据你的实际环境修改配置

3. **使用环境变量**：
   - Docker Compose 会自动加载 `.env` 文件
   - Python 应用需要手动加载（可以使用 `python-dotenv` 库）

## 环境变量清单

### OpenSearch 配置

| 变量名 | 说明 | 默认值 | 使用位置 |
|--------|------|--------|----------|
| `OPENSEARCH_NODE` | OpenSearch 节点地址 | `http://localhost:9200` | `backend/opensearch/client.py` |
| `OPENSEARCH_USERNAME` | OpenSearch 用户名 | `admin` | `backend/opensearch/client.py` |
| `OPENSEARCH_PASSWORD` | OpenSearch 密码 | `OpenSearch@2024!Dev` | `backend/opensearch/client.py`, `docker-compose.yml` |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | 容器初始化密码 | `OpenSearch@2024!Dev` | `docker-compose.yml` |
| `OPENSEARCH_JAVA_OPTS` | JVM 内存配置 | `-Xms512m -Xmx512m` | `docker-compose.yml` |

### Neo4j 配置

| 变量名 | 说明 | 默认值 | 使用位置 |
|--------|------|--------|----------|
| `NEO4J_URI` | Neo4j 连接 URI | `bolt://localhost:7687` | `graph/api.py` |
| `NEO4J_USER` | Neo4j 用户名 | `neo4j` | `graph/api.py` |
| `NEO4J_PASSWORD` | Neo4j 密码 | `password` | `graph/api.py`, `docker-compose.yml` |
| `NEO4J_DATABASE` | Neo4j 数据库名称 | (可选) | `graph/api.py` |
| `NEO4J_AUTH` | Neo4j 认证（格式: 用户名/密码） | `neo4j/password` | `docker-compose.yml` |
| `NEO4J_server_memory_*` | Neo4j 内存配置 | `1G` | `docker-compose.yml` |

### Backend 应用配置

| 变量名 | 说明 | 默认值 | 使用位置 |
|--------|------|--------|----------|
| `APP_NAME` | 应用名称 | `Attack Trace Analyzer API` | `backend/app/core/config.py` |
| `APP_ENV` | 应用环境 | `dev` | `backend/app/core/config.py` |
| `APP_VERSION` | 应用版本 | `0.1.0` | `backend/app/core/config.py` |
| `LOG_LEVEL` | 日志级别 | `INFO` | `backend/app/core/config.py` |

## 在 Python 代码中使用环境变量

### 方式一：直接使用 `os.getenv`（已实现）

```python
import os

node_url = os.getenv("OPENSEARCH_NODE", "http://localhost:9200")
```

### 方式二：使用 `python-dotenv`（推荐，可选）

如果需要在 Python 应用中自动加载 `.env` 文件：

1. **安装依赖**：
   ```bash
   pip install python-dotenv
   # 或使用 uv
   uv add python-dotenv
   ```

2. **在应用启动时加载**：
   ```python
   from dotenv import load_dotenv
   
   # 加载 .env 文件
   load_dotenv()
   
   # 然后正常使用 os.getenv
   import os
   node_url = os.getenv("OPENSEARCH_NODE")
   ```

3. **建议在以下位置加载**：
   - `backend/app/main.py` 文件开头
   - `graph/api.py` 或入口文件开头

## Docker Compose 使用

`docker-compose.yml` 已配置为自动加载 `.env` 文件：

```yaml
services:
  opensearch:
    env_file:
      - .env
    environment:
      - OPENSEARCH_INITIAL_ADMIN_PASSWORD=${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-OpenSearch@2024!Dev}
```

格式 `${VARIABLE:-default}` 表示如果环境变量不存在，使用默认值。

## 注意事项

1. **不要提交 `.env` 文件**：`.env` 已添加到 `.gitignore`，但 `.env.example` 会被提交
2. **不同环境使用不同的 `.env` 文件**：
   - 开发环境：`.env`
   - 生产环境：`.env.prod`（需要手动创建）
3. **敏感信息**：生产环境请使用强密码，不要使用默认密码
4. **Docker Compose**：确保在运行 `docker-compose up` 之前，`.env` 文件存在于项目根目录

## 代码中的环境变量使用情况

### Graph 模块 (`graph/api.py`)
- ✅ `NEO4J_URI` - 已使用 `os.getenv`
- ✅ `NEO4J_USER` - 已使用 `os.getenv`
- ✅ `NEO4J_PASSWORD` - 已使用 `os.getenv`
- ✅ `NEO4J_DATABASE` - 已使用 `os.getenv`

### Backend 模块

#### `backend/opensearch/client.py`
- ✅ `OPENSEARCH_NODE` - 已使用 `os.getenv`
- ✅ `OPENSEARCH_USERNAME` - 已使用 `os.getenv`
- ✅ `OPENSEARCH_PASSWORD` - 已使用 `os.getenv`

#### `backend/app/core/config.py`
- ✅ `APP_NAME` - 已使用 `os.getenv`
- ✅ `APP_ENV` - 已使用 `os.getenv`
- ✅ `APP_VERSION` - 已使用 `os.getenv`
- ✅ `LOG_LEVEL` - 已使用 `os.getenv`

## 验证配置

启动 Docker Compose 服务后，可以验证环境变量是否正确加载：

```bash
# 检查 OpenSearch 是否可访问
curl -u admin:${OPENSEARCH_PASSWORD} http://localhost:9200

# 检查 Neo4j 连接
# 访问 http://localhost:7474 使用浏览器界面
```

## 更新历史

- 2026-01-13: 创建统一的环境变量管理系统
