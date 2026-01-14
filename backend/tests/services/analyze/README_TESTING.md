# killchain_llm.py 测试指南

本文档介绍如何运行 `killchain_llm.py` 模块的测试。

## 快速开始

### 1. 运行所有测试

在 `backend` 目录下运行：

```bash
# 使用 Python
python -m pytest tests/services/analyze/test_killchain_llm.py -v

# 使用 uv（推荐）
uv run pytest tests/services/analyze/test_killchain_llm.py -v
```

### 2. 运行特定测试类

```bash
# 只测试 PayloadReducer
uv run pytest tests/services/analyze/test_killchain_llm.py::TestPayloadReducer -v

# 只测试 LLMChooser
uv run pytest tests/services/analyze/test_killchain_llm.py::TestLLMChooser -v
```

### 3. 运行单个测试方法

```bash
# 测试特定方法
uv run pytest tests/services/analyze/test_killchain_llm.py::TestPayloadReducer::test_reduce_basic -v
```

## 常用测试命令

### 基本运行

```bash
# 运行所有测试，显示详细信息
uv run pytest tests/services/analyze/test_killchain_llm.py -v

# 运行所有测试，简短输出
uv run pytest tests/services/analyze/test_killchain_llm.py

# 运行所有测试，显示详细错误信息
uv run pytest tests/services/analyze/test_killchain_llm.py -v --tb=short
```

### 按测试类运行

```bash
# PayloadReducer 相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestPayloadReducer -v

# HeuristicPreselector 相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestHeuristicPreselector -v

# build_choose_prompt 相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestBuildChoosePrompt -v

# JSON 提取相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestExtractJsonObj -v

# 结果验证相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestValidateChooseResult -v

# 回退选择相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestFallbackChoose -v

# MockChooser 相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestMockChooser -v

# LLMChooser 相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestLLMChooser -v

# 工厂函数相关测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestCreateLLMClient -v

# 集成测试
uv run pytest tests/services/analyze/test_killchain_llm.py::TestIntegration -v
```

### 按关键字过滤

```bash
# 运行包含 "reduce" 的测试
uv run pytest tests/services/analyze/test_killchain_llm.py -k "reduce" -v

# 运行包含 "llm" 的测试
uv run pytest tests/services/analyze/test_killchain_llm.py -k "llm" -v

# 运行包含 "json" 的测试
uv run pytest tests/services/analyze/test_killchain_llm.py -k "json" -v
```

## 测试覆盖率

### 生成覆盖率报告

```bash
# 安装覆盖率工具（如果未安装）
uv add pytest-cov

# 运行测试并生成覆盖率报告
uv run pytest tests/services/analyze/test_killchain_llm.py --cov=app.services.analyze.killchain_llm --cov-report=term --cov-report=html

# 查看 HTML 报告
# 打开 backend/htmlcov/index.html
```

### 查看覆盖率详情

```bash
# 终端显示覆盖率
uv run pytest tests/services/analyze/test_killchain_llm.py --cov=app.services.analyze.killchain_llm --cov-report=term-missing

# 生成 HTML 报告
uv run pytest tests/services/analyze/test_killchain_llm.py --cov=app.services.analyze.killchain_llm --cov-report=html
```

## 测试输出选项

### 详细输出

```bash
# -v: 详细模式（显示每个测试）
uv run pytest tests/services/analyze/test_killchain_llm.py -v

# -vv: 更详细（显示断言详情）
uv run pytest tests/services/analyze/test_killchain_llm.py -vv

# -s: 显示 print 输出
uv run pytest tests/services/analyze/test_killchain_llm.py -v -s
```

### 错误追踪

```bash
# --tb=short: 简短错误追踪
uv run pytest tests/services/analyze/test_killchain_llm.py --tb=short

# --tb=long: 详细错误追踪
uv run pytest tests/services/analyze/test_killchain_llm.py --tb=long

# --tb=line: 单行错误追踪
uv run pytest tests/services/analyze/test_killchain_llm.py --tb=line

# --tb=no: 不显示错误追踪
uv run pytest tests/services/analyze/test_killchain_llm.py --tb=no
```

## 测试报告

### 生成 HTML 报告

```bash
# 安装报告插件（如果未安装）
uv add pytest-html

# 生成 HTML 报告
uv run pytest tests/services/analyze/test_killchain_llm.py --html=test_report.html --self-contained-html

# 查看报告
# 打开 backend/test_report.html
```

### 生成 JUnit XML 报告（CI/CD）

```bash
uv run pytest tests/services/analyze/test_killchain_llm.py --junitxml=test_results.xml
```

## 调试测试

### 在失败时进入调试器

```bash
# 安装 pytest 调试插件（如果未安装）
uv add pytest-pdb

# 测试失败时自动进入调试器
uv run pytest tests/services/analyze/test_killchain_llm.py --pdb
```

### 只运行失败的测试

```bash
# 第一次运行（会失败）
uv run pytest tests/services/analyze/test_killchain_llm.py

# 只运行上次失败的测试
uv run pytest tests/services/analyze/test_killchain_llm.py --lf

# 先运行失败的，再运行其他的
uv run pytest tests/services/analyze/test_killchain_llm.py --ff
```

## 性能测试

### 显示最慢的测试

```bash
# 安装性能插件（如果未安装）
uv add pytest-timeout

# 显示最慢的 10 个测试
uv run pytest tests/services/analyze/test_killchain_llm.py --durations=10
```

## 并行运行（加速）

```bash
# 安装并行插件（如果未安装）
uv add pytest-xdist

# 使用 4 个进程并行运行
uv run pytest tests/services/analyze/test_killchain_llm.py -n 4

# 自动检测 CPU 核心数
uv run pytest tests/services/analyze/test_killchain_llm.py -n auto
```

## 完整示例

### 完整的测试命令（推荐）

```bash
# 运行所有测试，显示详细信息，生成覆盖率报告
uv run pytest tests/services/analyze/test_killchain_llm.py \
    -v \
    --tb=short \
    --cov=app.services.analyze.killchain_llm \
    --cov-report=term-missing \
    --cov-report=html \
    --html=test_report.html \
    --self-contained-html
```

## 测试统计

当前测试文件包含：
- **42 个测试用例**
- **10 个测试类**
- 覆盖所有主要功能模块

### 测试分布

- PayloadReducer: 4 个测试
- HeuristicPreselector: 4 个测试
- build_choose_prompt: 2 个测试
- _extract_json_obj: 5 个测试
- validate_choose_result: 5 个测试
- fallback_choose: 3 个测试
- MockChooser: 2 个测试
- LLMChooser: 6 个测试
- create_llm_client: 8 个测试
- 集成测试: 3 个测试

## 常见问题

### Q: 测试失败怎么办？

A: 使用 `-v --tb=short` 查看详细错误信息：
```bash
uv run pytest tests/services/analyze/test_killchain_llm.py -v --tb=short
```

### Q: 如何只运行新添加的测试？

A: 使用 `-k` 参数按关键字过滤：
```bash
uv run pytest tests/services/analyze/test_killchain_llm.py -k "test_new_feature" -v
```

### Q: 如何跳过某些测试？

A: 使用 `@pytest.mark.skip` 装饰器，或使用 `-m` 参数：
```bash
# 跳过标记为 slow 的测试
uv run pytest tests/services/analyze/test_killchain_llm.py -m "not slow"
```

## 在 IDE 中运行

### VS Code

1. 安装 Python 扩展
2. 打开测试文件
3. 点击测试方法上方的 "Run Test" 按钮
4. 或使用快捷键 `Ctrl+Shift+P` -> "Python: Run Tests"

### PyCharm

1. 右键点击测试文件或测试方法
2. 选择 "Run 'pytest in test_killchain_llm.py'"
3. 或使用快捷键 `Ctrl+Shift+F10`

## 持续集成

### GitHub Actions 示例

```yaml
- name: Run killchain_llm tests
  run: |
    cd backend
    uv run pytest tests/services/analyze/test_killchain_llm.py -v --tb=short --junitxml=test_results.xml
```
