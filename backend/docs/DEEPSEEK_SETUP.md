# DeepSeek LLM 配置指南

## 概述

本项目已从 OpenAI 迁移到 DeepSeek LLM。DeepSeek 提供免费 API 额度，兼容 OpenAI API 格式，支持中文处理。

## 快速开始

### 1. 获取 DeepSeek API Key

1. 访问 [DeepSeek 平台](https://platform.deepseek.com/)
2. 注册/登录账户
3. 进入 [API Keys 页面](https://platform.deepseek.com/api_keys)
4. 创建新的 API Key（格式：`sk-xxx...`）

### 2. 配置环境变量

#### 方法 1: 使用 .env 文件（推荐）

```bash
cd backend
cp .env.example .env
```

编辑 `backend/.env` 文件：

```bash
# LLM 配置
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=sk-your-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
DEEPSEEK_MODEL=deepseek-chat
LLM_TIMEOUT=30.0
LLM_MAX_RETRIES=2
```

#### 方法 2: 使用环境变量

```bash
export LLM_PROVIDER=deepseek
export DEEPSEEK_API_KEY=sk-your-api-key-here
export DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
export DEEPSEEK_MODEL=deepseek-chat
```

### 3. 使用 Mock 模式（调试）

如果不想使用真实 LLM，可以设置为 mock 模式：

```bash
LLM_PROVIDER=mock
```

Mock 模式会使用本地启发式算法选择路径，无需 API Key。

## 环境变量说明

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `LLM_PROVIDER` | `mock` | LLM 提供商：`deepseek` 或 `mock` |
| `DEEPSEEK_API_KEY` | `""` | DeepSeek API Key（从平台获取） |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1` | DeepSeek API 基础 URL |
| `DEEPSEEK_MODEL` | `deepseek-chat` | 使用的模型名称 |
| `LLM_TIMEOUT` | `30.0` | 请求超时时间（秒） |
| `LLM_MAX_RETRIES` | `2` | 最大重试次数 |

## 测试配置

运行测试脚本验证配置：

```bash
docker compose exec python python scripts/test_llm_connection.py
```

## DeepSeek vs OpenAI

### 优势

- ✅ **免费额度**：每日有一定免费调用次数
- ✅ **中文支持**：对中文理解更好
- ✅ **API 兼容**：完全兼容 OpenAI API 格式
- ✅ **性能优秀**：响应速度快

### 迁移说明

从 OpenAI 迁移到 DeepSeek 只需：

1. 将 `LLM_PROVIDER` 从 `openai` 改为 `deepseek`
2. 将 `OPENAI_API_KEY` 改为 `DEEPSEEK_API_KEY`
3. 将 `OPENAI_BASE_URL` 改为 `DEEPSEEK_BASE_URL`
4. 将 `OPENAI_MODEL` 改为 `DEEPSEEK_MODEL`

代码层面无需修改，因为 DeepSeek 兼容 OpenAI API 格式。

## 常见问题

### Q: 如何查看 API 使用情况？

A: 登录 [DeepSeek 平台](https://platform.deepseek.com/)，在控制台查看使用量和剩余额度。

### Q: 免费额度用完了怎么办？

A: 可以：
1. 等待额度重置（通常每日重置）
2. 升级到付费计划
3. 临时切换到 `mock` 模式进行调试

### Q: 支持其他 LLM 提供商吗？

A: 当前代码支持任何兼容 OpenAI API 格式的提供商（如 Groq、本地部署的模型等），只需修改 `base_url` 和 `model` 参数即可。

## 参考链接

- [DeepSeek 官方文档](https://platform.deepseek.com/docs)
- [DeepSeek API Keys](https://platform.deepseek.com/api_keys)
- [OpenAI Python SDK](https://github.com/openai/openai-python)（DeepSeek 兼容）
