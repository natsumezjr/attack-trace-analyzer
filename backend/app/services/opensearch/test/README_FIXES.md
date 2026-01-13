# 测试导入问题修复说明

## 问题

测试运行时出现导入错误：
- `ImportError: cannot import name 'get_client' from 'opensearch'`
- `ModuleNotFoundError: No module named 'opensearch.index'`

## 原因

1. **路径设置问题**：测试文件需要正确设置Python路径，以便能够导入 `backend.opensearch` 模块
2. **导入方式问题**：部分函数（如 `generate_fingerprint`）没有在 `__init__.py` 中导出，需要从子模块导入

## 修复方案

### 1. 修复路径设置

所有测试文件都需要正确设置路径：

```python
test_dir = Path(__file__).parent
parent_dir = test_dir.parent  # backend/opensearch
backend_dir = parent_dir.parent  # backend
sys.path.insert(0, str(backend_dir))  # 确保backend目录在路径中
sys.path.insert(0, str(parent_dir))  # 也添加opensearch目录
```

### 2. 统一导入方式

- **公开API**：从 `opensearch` 导入（如 `get_client`, `store_events`）
- **内部函数**：从子模块导入（如 `opensearch.analysis.generate_fingerprint`）

### 3. 修复索引名称格式检查

索引名称格式已改为使用连字符（`-`）而不是点号（`.`），测试需要相应更新。

## 已修复的文件

- ✅ `conftest.py` - 修复路径设置和导入
- ✅ `test_unit_opensearch.py` - 修复所有导入和索引格式检查
- ✅ `test_analysis_incremental.py` - 修复路径设置
- ✅ `test_integration_full.py` - 修复路径设置
- ✅ `test_system_opensearch.py` - 修复路径设置

## 运行测试

确保在 `backend` 目录下运行测试：

```bash
cd backend
uv run pytest opensearch/test/ -v
```
