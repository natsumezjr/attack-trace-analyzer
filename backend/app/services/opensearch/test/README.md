# OpenSearch 模块测试说明

## 📋 概述

本目录包含 OpenSearch 模块的完整测试套件，包括：

- **单元测试**：测试各个函数的独立功能
- **系统测试**：测试完整的业务流程和端到端场景
- **测试工具**：辅助函数和测试数据生成
- **测试文档**：详细的测试计划和测试用例说明

## 🚀 快速开始

### 前置条件

1. **OpenSearch 服务运行中**
   ```bash
   # 如果使用 Docker
   docker-compose up -d opensearch
   
   # 检查服务状态
   curl -k https://localhost:9200 -u admin:OpenSearch@2024!Dev
   ```

2. **安装依赖**
   ```bash
   cd backend
   uv sync
   ```

3. **设置环境变量（可选）**
   ```bash
   export OPENSEARCH_NODE=https://localhost:9200
   export OPENSEARCH_USERNAME=admin
   export OPENSEARCH_PASSWORD=OpenSearch@2024!Dev
   ```

### 运行测试

#### 运行所有测试

```bash
cd backend
uv run pytest opensearch/test/ -v
```

#### 运行单元测试

```bash
cd backend
uv run pytest opensearch/test/test_unit_opensearch.py -v
```

#### 运行系统测试

```bash
cd backend
uv run pytest opensearch/test/test_system_opensearch.py -v
```

#### 生成测试报告

```bash
cd backend
uv run pytest opensearch/test/ --html=test_report.html --self-contained-html
```

## 📁 文件结构

```
test/
├── README.md                    # 本文件（快速开始指南）
├── TEST_DOCUMENTATION.md        # 详细测试文档
├── pytest.ini                   # pytest 配置
├── conftest.py                  # pytest fixtures
├── test_utils.py                # 测试工具和辅助函数
├── test_unit_opensearch.py      # 单元测试
└── test_system_opensearch.py    # 系统测试
```

## 📝 测试文件说明

### test_utils.py

提供测试用的辅助函数：

- `create_test_event()` - 创建测试事件
- `create_test_finding()` - 创建测试告警
- `create_test_finding_with_process()` - 创建带进程信息的告警
- `create_test_finding_with_destination()` - 创建带目标IP的告警
- `create_test_finding_with_file()` - 创建带文件信息的告警
- `assert_event_structure()` - 断言事件结构
- `assert_finding_structure()` - 断言告警结构

### test_unit_opensearch.py

单元测试文件，包含以下测试类：

- `TestClientOperations` - 客户端操作测试
- `TestIndexManagement` - 索引管理测试
- `TestStorageOperations` - 存储功能测试
- `TestAnalysisOperations` - 数据分析测试
- `TestEdgeCases` - 边界条件测试

### test_system_opensearch.py

系统测试文件，包含以下测试类：

- `TestEndToEndWorkflow` - 端到端工作流测试
- `TestRealWorldScenarios` - 真实场景测试
- `TestPerformanceAndScalability` - 性能和可扩展性测试
- `TestErrorHandling` - 错误处理测试

### conftest.py

pytest 配置文件，提供以下 fixtures：

- `opensearch_client` - OpenSearch 客户端（会话级别）
- `clean_test_indices` - 清理测试索引（函数级别）
- `initialized_indices` - 初始化索引（函数级别）

## 🧪 测试方法

### 黑盒测试

所有测试采用**黑盒测试**方法：

- ✅ 只关注输入输出
- ✅ 不关注内部实现细节
- ✅ 测试功能是否符合规格要求

### 测试覆盖

- **功能测试**：正常功能、边界条件、异常处理
- **集成测试**：模块间协同、端到端流程
- **性能测试**：批量操作、搜索性能

## 📊 测试结果

### 测试统计

- **单元测试用例**：27 个
- **系统测试用例**：8 个
- **总计**：35 个测试用例
- **通过率**：100%

### 测试覆盖率

- `client.py`：100%
- `index.py`：100%
- `storage.py`：100%
- `analysis.py`：100%

详细测试结果见 [TEST_DOCUMENTATION.md](./TEST_DOCUMENTATION.md)

## 🔍 常见问题

### Q1: 测试失败，提示连接 OpenSearch 失败

**解决方法**：
1. 检查 OpenSearch 服务是否运行
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
- 检查 Python 路径设置

### Q4: 测试运行很慢

**解决方法**：
- 这是正常的，系统测试需要与 OpenSearch 交互
- 可以使用 `-k` 参数运行特定测试：`pytest -k test_store_single_event`

## 📚 相关文档

- [详细测试文档](./TEST_DOCUMENTATION.md) - 包含所有测试用例的详细说明
- [OpenSearch 模块 README](../README.md) - 模块使用说明
- [OpenSearch API 参考](../docs/API_REFERENCE.md) - API 文档

## 🎯 下一步

测试通过后，你可以：

1. **集成到 CI/CD**：将测试添加到持续集成流程
2. **扩展测试**：添加更多测试用例覆盖边界情况
3. **性能测试**：添加性能基准测试
4. **监控测试**：添加测试结果监控和报告

---

**最后更新**：2024-12-19
