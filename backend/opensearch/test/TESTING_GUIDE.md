# 测试指南

本文档提供完整的测试规范和使用指南。

## 📋 测试分类

### 1. 单元测试（Unit Tests）

**位置**：`test_unit_opensearch.py`, `test_analysis_incremental.py`

**特点**：
- ✅ 快速执行（秒级）
- ✅ 不依赖外部服务（可mock）
- ✅ 测试单个函数/类的功能
- ✅ 黑盒测试：只关注输入输出

**运行方式**：
```bash
# 运行所有单元测试
pytest opensearch/test/ -m unit -v

# 运行特定测试文件
pytest opensearch/test/test_unit_opensearch.py -v
```

### 2. 集成测试（Integration Tests）

**位置**：`test_system_opensearch.py`, `test_integration_full.py`

**特点**：
- ⚠️ 需要OpenSearch服务运行
- ⚠️ 执行时间较长（分钟级）
- ✅ 测试模块间协同
- ✅ 测试端到端流程

**运行方式**：
```bash
# 运行所有集成测试
pytest opensearch/test/ -m integration -v

# 运行特定测试文件
pytest opensearch/test/test_system_opensearch.py -v
```

### 3. 系统测试（System Tests）

**位置**：`test_system_opensearch.py`

**特点**：
- ✅ 测试完整业务流程
- ✅ 测试真实场景
- ✅ 测试性能和可扩展性

## 🚀 快速开始

### 前置条件

1. **启动OpenSearch服务**
   ```bash
   docker-compose up -d opensearch
   ```

2. **安装测试依赖**
   ```bash
   cd backend
   uv sync
   uv add pytest pytest-html pytest-cov
   ```

3. **设置环境变量**（可选）
   ```bash
   export OPENSEARCH_NODE=https://localhost:9200
   export OPENSEARCH_USERNAME=admin
   export OPENSEARCH_PASSWORD=OpenSearch@2024!Dev
   ```

### 运行测试

#### 方式1：使用测试脚本（推荐）

**Linux/macOS**：
```bash
cd backend/opensearch/test
chmod +x run_tests.sh
./run_tests.sh
```

**Windows**：
```powershell
cd backend\opensearch\test
.\run_tests.ps1
```

#### 方式2：直接使用pytest

```bash
cd backend

# 运行所有测试
uv run pytest opensearch/test/ -v

# 运行单元测试
uv run pytest opensearch/test/ -m unit -v

# 运行集成测试
uv run pytest opensearch/test/ -m integration -v

# 运行特定测试文件
uv run pytest opensearch/test/test_unit_opensearch.py -v

# 运行特定测试类
uv run pytest opensearch/test/test_unit_opensearch.py::TestClientOperations -v

# 运行特定测试函数
uv run pytest opensearch/test/test_unit_opensearch.py::TestClientOperations::test_get_client -v
```

## 📊 测试覆盖率

### 生成覆盖率报告

```bash
cd backend
uv run pytest opensearch/test/ \
    --cov=opensearch \
    --cov-report=html \
    --cov-report=term
```

报告位置：
- HTML报告：`htmlcov/index.html`
- 终端报告：直接输出到终端

### 覆盖率目标

- **单元测试覆盖率**：≥ 80%
- **集成测试覆盖率**：≥ 60%
- **关键函数覆盖率**：100%

## 🧪 测试编写规范

### 1. 测试文件命名

- 单元测试：`test_unit_*.py`
- 集成测试：`test_integration_*.py`
- 系统测试：`test_system_*.py`

### 2. 测试类命名

```python
class TestFunctionalityName:
    """测试功能描述"""
    pass
```

### 3. 测试函数命名

```python
def test_what_we_are_testing(self, fixture_name):
    """测试描述：测试什么，期望什么结果"""
    # Arrange: 准备测试数据
    # Act: 执行被测试的函数
    # Assert: 验证结果
```

### 4. 使用标记（Markers）

```python
@pytest.mark.unit
def test_something():
    """单元测试"""
    pass

@pytest.mark.integration
@pytest.mark.slow
def test_something_slow():
    """慢速集成测试"""
    pass
```

### 5. 使用Fixtures

```python
def test_something(initialized_indices):
    """使用fixture初始化索引"""
    # 测试代码
    pass
```

## 📝 测试用例示例

### 单元测试示例

```python
@pytest.mark.unit
class TestStorageOperations:
    """测试存储功能"""
    
    def test_store_single_event(self, initialized_indices):
        """测试存储单个事件"""
        from opensearch import store_events
        from test_utils import create_test_event
        
        event = create_test_event("evt-001")
        result = store_events([event])
        
        assert result["success"] == 1
        assert result["failed"] == 0
```

### 集成测试示例

```python
@pytest.mark.integration
class TestEndToEndWorkflow:
    """端到端工作流测试"""
    
    def test_complete_workflow(self, initialized_indices):
        """测试完整工作流"""
        from opensearch import store_events, deduplicate_findings
        
        # Step 1: 存储事件
        # Step 2: 执行去重
        # Step 3: 验证结果
        pass
```

## 🔍 调试测试

### 运行单个测试并输出详细信息

```bash
pytest opensearch/test/test_unit_opensearch.py::TestClientOperations::test_get_client -v -s
```

### 使用pdb调试

```python
def test_something():
    import pdb; pdb.set_trace()
    # 测试代码
```

### 查看测试输出

```bash
pytest opensearch/test/ -v -s --log-cli-level=DEBUG
```

## 📚 测试工具函数

### test_utils.py

提供以下辅助函数：

- `create_test_event()` - 创建测试事件
- `create_test_finding()` - 创建测试告警
- `create_test_finding_with_process()` - 创建带进程信息的告警
- `create_test_finding_with_destination()` - 创建带目标IP的告警
- `create_test_finding_with_file()` - 创建带文件信息的告警
- `assert_event_structure()` - 断言事件结构
- `assert_finding_structure()` - 断言告警结构

## 🎯 测试最佳实践

1. **测试独立性**：每个测试应该独立，不依赖其他测试
2. **测试可重复性**：测试应该可以重复运行，结果一致
3. **测试快速性**：单元测试应该快速执行
4. **测试清晰性**：测试代码应该清晰易懂
5. **测试完整性**：覆盖正常流程、边界条件、异常情况

## 🐛 常见问题

### Q1: 测试失败，提示连接OpenSearch失败

**解决方法**：
1. 检查OpenSearch服务是否运行：`curl -k https://localhost:9200 -u admin:password`
2. 检查环境变量是否正确设置
3. 检查网络连接和防火墙设置

### Q2: 测试失败，提示索引已存在

**解决方法**：
- 这是正常的，`conftest.py` 中的 `clean_test_indices` fixture 会自动清理
- 如果仍有问题，可以手动删除测试索引

### Q3: 导入错误

**解决方法**：
- 确保在 `backend` 目录下运行测试
- 确保已安装所有依赖：`uv sync`
- 检查Python路径设置

### Q4: 测试运行很慢

**解决方法**：
- 使用 `-m unit` 只运行单元测试（快速）
- 使用 `-k` 参数运行特定测试：`pytest -k test_store_single_event`
- 集成测试本身较慢，这是正常的

## 📈 CI/CD集成

### GitHub Actions示例

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          pip install uv
          cd backend && uv sync
      - name: Start OpenSearch
        run: docker-compose up -d opensearch
      - name: Run tests
        run: |
          cd backend
          uv run pytest opensearch/test/ -v --cov=opensearch --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

## 📖 相关文档

- [测试README](./README.md) - 快速开始指南
- [测试文档](./TEST_DOCUMENTATION.md) - 详细测试用例说明
- [OpenSearch模块README](../README.md) - 模块使用说明
