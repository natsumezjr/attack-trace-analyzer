# 测试脚本目录

开发过程测试目录，用于临时测试某些功能。这个目录包含正式测试脚本和工具脚本，用于验证Security Analytics集成功能。

## 正式测试脚本

这些脚本在 `docs/进度总结.md` 中被引用，用于验证各个功能模块：

### 核心功能测试

- **`test_findings_conversion.py`** - 测试findings转换和存储功能
  - 验证Security Analytics的findings能正确转换为ECS格式
  - 验证转换后的findings能存储到`raw-findings-*`索引
  - 验证字段映射正确性

- **`test_deduplication.py`** - 测试告警去重功能
  - 验证相同指纹的findings能正确合并
  - 验证canonical findings的生成和存储
  - 验证去重逻辑的正确性

- **`test_full_flow.py`** - 测试完整流程（端到端）
  - 验证从事件收集到canonical findings的完整流程
  - 验证检测和去重两个阶段的协调工作
  - 验证数据完整性

- **`test_storage_with_clear.py`** - 测试存储功能（带数据清除）
  - 先清除已有数据，再测试存储功能
  - 用于验证存储功能是否真的工作（避免重复跳过的情况）

## 工具脚本

- **`clear_findings.py`** - 清除已有的findings数据
  - 交互式清除raw-findings和canonical-findings数据
  - 用于测试前清理环境

## 使用方法

所有测试脚本都可以通过以下方式运行：

```powershell
cd d:\Coding\Project\attack-trace-analyzer\backend\opensearch\temp_tests
uv run python <脚本名>.py
```

## 注意事项

- 这些脚本是正式测试脚本，应该保留
- 如果修改了核心功能（`analysis.py`, `storage.py`等），应该运行这些测试脚本验证
- 测试脚本会自动处理路径和导入问题，可以从任何目录运行
