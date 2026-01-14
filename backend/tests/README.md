# 测试体系文档

## 目录结构

```
tests/
├── unit/                    # 单元测试（无外部依赖）
│   ├── test_core/          # 核心模块测试
│   ├── test_dto/           # 数据传输对象测试
│   ├── test_services_analyze/    # 分析服务单元测试
│   ├── test_services_neo4j/       # Neo4j服务单元测试
│   └── test_services_opensearch/  # OpenSearch服务单元测试
│
├── integration/             # 集成测试（需要外部服务）
│   ├── test_api/           # API路由集成测试
│   ├── test_services_neo4j/       # Neo4j集成测试
│   └── test_services_opensearch/  # OpenSearch集成测试
│
├── e2e/                     # 端到端测试（完整业务流程）
│
├── benchmarks/              # 性能测试
│
└── fixtures/                # 测试数据和工具
    ├── common.py           # 通用工具函数
    ├── graph/              # 图测试数据（JSON）
    ├── mocks/              # 测试数据工厂
    │   ├── event_factory.py
    │   ├── finding_factory.py
    │   └── graph_factory.py
    └── opensearch/         # OpenSearch测试数据
```

## 运行测试

### 按类型运行

```bash
# 只运行单元测试（快速，无外部依赖）
pytest -m unit -v

# 只运行集成测试（需要OpenSearch/Neo4j）
pytest -m integration -v

# 只运行E2E测试（完整业务流程）
pytest -m e2e -v

# 排除慢测试
pytest -m "not slow" -v
```

### 按模块运行

```bash
# 测试API模块
pytest tests/integration/test_api/ -v

# 测试OpenSearch模块
pytest -m requires_opensearch -v

# 测试Neo4j模块
pytest -m requires_neo4j -v

# 测试分析模块
pytest tests/unit/test_services_analyze/ -v
```

### 覆盖率报告

```bash
# 生成覆盖率报告
pytest --cov=app --cov-report=html

# 查看HTML报告
open htmlcov/index.html
```

## 测试标记说明

### 测试层级
- `unit`: 单元测试（无外部依赖，快速）
- `integration`: 集成测试（需要外部服务）
- `e2e`: 端到端测试（完整业务流程）
- `system`: 系统测试（多组件协同）

### 速度
- `slow`: 慢速测试（>1秒）
- `fast`: 快速测试（<1秒）

### 外部依赖
- `requires_opensearch`: 需要OpenSearch实例
- `requires_neo4j`: 需要Neo4j实例
- `requires_llm`: 需要LLM服务（OpenAI等）

### 模块
- `api`: API路由测试
- `opensearch`: OpenSearch模块测试
- `neo4j`: Neo4j模块测试
- `analyze`: 分析模块测试
- `scheduler`: 定时任务测试

## 编写新测试

### 单元测试示例

```python
import pytest

pytestmark = pytest.mark.unit

class TestMyFeature:
    @pytest.mark.asyncio
    async def test_something(self, mock_opensearch_client):
        """测试某个功能"""
        # 使用mock fixtures
        result = my_function(mock_opensearch_client)
        assert result is not None
```

### 集成测试示例

```python
import pytest

pytestmark = pytest.mark.integration

class TestMyAPI:
    @pytest.mark.asyncio
    async def test_api_endpoint(self, async_client, initialized_indices):
        """测试API端点"""
        response = await async_client.get("/api/v1/endpoint")
        assert response.status_code == 200
```

## Fixtures使用

### 单元测试Fixtures

- `mock_opensearch_client`: 模拟的OpenSearch客户端
- `mock_neo4j_session`: 模拟的Neo4j会话
- `mock_llm_client`: 模拟的LLM客户端
- `sample_event`: 示例事件数据
- `sample_finding`: 示例告警数据

### 集成测试Fixtures

- `opensearch_client`: 真实的OpenSearch客户端（session-scoped）
- `clean_test_indices`: 清理测试索引（每次测试前）
- `initialized_indices`: 初始化所有索引
- `neo4j_driver`: 真实的Neo4j驱动（session-scoped）
- `clean_neo4j_db`: 清理Neo4j数据库（每次测试前）
- `async_client`: FastAPI异步测试客户端

### E2E测试Fixtures

- `full_test_environment`: 完整测试环境（OpenSearch + Neo4j）

## 测试数据工厂

### EventFactory

```python
from tests.fixtures.mocks.event_factory import EventFactory

# 创建基础事件
event = EventFactory.create_base_event()

# 创建Falco事件
falco_event = EventFactory.create_falco_event(rule="Test rule")

# 创建Suricata事件
suricata_event = EventFactory.create_suricata_event(signature="Test alert")
```

### FindingFactory

```python
from tests.fixtures.mocks.finding_factory import FindingFactory

# 创建原始告警
raw_finding = FindingFactory.create_raw_finding(technique_id="T1078")

# 创建规范告警
canonical_finding = FindingFactory.create_canonical_finding()
```

### GraphFactory

```python
from tests.fixtures.mocks.graph_factory import GraphFactory

# 创建节点
node = GraphFactory.create_node("Host:h-001", "Host", props={"host.id": "h-001"})

# 创建边
edge = GraphFactory.create_edge("Process:p-001", "File:f-001", "WROTE", props={"event.id": "evt-001"})

# 创建测试图
nodes, edges = GraphFactory.create_test_graph()
```

## 环境变量

```bash
# 控制OpenSearch测试运行
export RUN_OPENSEARCH_TESTS=1  # 默认不运行

# 控制Neo4j测试运行
export RUN_NEO4J_TESTS=1       # 默认运行

# 控制LLM测试运行
export RUN_LLM_TESTS=1         # 默认不运行
```

## 常见问题

### Q: 如何跳过需要OpenSearch的测试？
A: 不设置 `RUN_OPENSEARCH_TESTS` 环境变量即可，测试会自动跳过。

### Q: 如何只运行某个模块的测试？
A: 使用 `pytest tests/unit/test_services_analyze/ -v`。

### Q: 测试失败了怎么办？
A: 检查是否启动了必要的服务（OpenSearch/Neo4j），或者查看测试日志获取详细信息。

## 贡献指南

1. 新增测试时，按照目录结构放置文件
2. 使用合适的pytest标记（unit/integration/e2e）
3. 使用测试数据工厂生成测试数据
4. 确保测试独立，不依赖执行顺序
5. 编写清晰的测试文档字符串
