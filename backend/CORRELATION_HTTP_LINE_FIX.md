# Correlation 查询 HTTP 行过长错误修复

## 问题描述

在 OpenSearch Dashboard 中查看 correlation 时，出现错误：
```
Failed to retrieve findings: [too_long_http_line_exception] An HTTP line is larger than 4096 bytes.
```

## 原因分析

OpenSearch 默认的 HTTP 请求行长度限制是 4096 字节（4KB）。当 Dashboard 查询 correlation 时，如果 URL 中包含大量 findings IDs 或其他长参数，就会超过这个限制。

## 解决方案

### 1. 修改后端代码使用 POST 请求（主要解决方案）

已修改 `backend/app/services/opensearch/analysis.py` 中的 `query_correlation_results` 函数：
- **优先使用 POST 请求**，将查询参数放在请求体中，避免 URL 过长
- 如果 POST 不支持，回退到 GET，但会限制 URL 长度

这是**推荐的解决方案**，因为：
- 不需要修改 OpenSearch 配置
- 避免了挂载配置文件可能导致的启动问题
- POST 请求的 body 没有长度限制（或限制很大）

### 2. 增加 OpenSearch HTTP 行长度限制（备选方案）

**注意**：`http.max_initial_line_length` 不能通过 API 动态设置，必须在启动时通过配置文件设置。

**问题**：直接挂载 `opensearch.yml` 会覆盖默认配置，可能导致容器启动失败。

**解决方案**：
1. **使用环境变量**（如果 OpenSearch 版本支持）：
   ```yaml
   environment:
     - HTTP_MAX_INITIAL_LINE_LENGTH=16kb
   ```

2. **创建完整的配置文件**（包含所有必要的默认配置）：
   - 需要从运行中的容器复制默认配置
   - 然后添加自定义配置
   - 这种方法比较复杂，不推荐

**当前状态**：配置文件挂载已注释掉，优先使用 POST 请求方案。

### 2. 修改后端代码使用 POST 请求

已修改 `backend/app/services/opensearch/analysis.py` 中的 `query_correlation_results` 函数：
- 优先使用 POST 请求，将查询参数放在请求体中
- 如果 POST 不支持，回退到 GET，但会限制 URL 长度

### 3. 应用配置

**重要**：需要重启 OpenSearch 容器才能应用新配置：

```bash
cd backend
docker compose restart opensearch
```

或者完全重启：

```bash
docker compose down opensearch
docker compose up -d opensearch
```

### 4. 验证配置

重启后，可以通过以下方式验证配置是否生效：

```bash
# 检查 OpenSearch 配置
curl -k -u admin:OpenSearch@2024!Dev https://localhost:9200/_cluster/settings?include_defaults=true | grep -i "max_initial_line_length"
```

或者使用 PowerShell：

```powershell
$headers = @{
    Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:OpenSearch@2024!Dev"))
}
Invoke-RestMethod -Uri "https://localhost:9200/_cluster/settings?include_defaults=true" -Headers $headers -SkipCertificateCheck | ConvertTo-Json -Depth 10 | Select-String "max_initial_line_length"
```

## 替代方案

如果不想修改 OpenSearch 配置，也可以：

1. **减少查询的 findings 数量**：在 Dashboard 中缩小时间范围或添加更多过滤条件
2. **使用 POST 请求**：确保所有 correlation 查询都使用 POST 而不是 GET（已在后端代码中实现）

## 注意事项

- 增加 HTTP 行长度限制可能会增加安全风险（DoS 攻击），但 16KB 是一个相对安全的范围
- 如果仍然遇到问题，可以进一步增加到 32KB，但不建议超过 64KB
- 确保 `opensearch.yml` 文件权限正确（容器内可读）

## 相关文件

- `backend/docker-compose.yml` - Docker Compose 配置（已添加 `HTTP_MAX_INITIAL_LINE_LENGTH` 环境变量）
- `backend/app/services/opensearch/analysis.py` - 后端 correlation 查询代码（已修改为使用 POST）

**注意**：`backend/opensearch.yml` 文件已不再需要，因为配置已通过环境变量设置。如果该文件存在，可以删除。
