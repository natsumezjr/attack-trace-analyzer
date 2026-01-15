# OpenSearch 版本信息

## 当前部署版本

### OpenSearch
- **镜像**: `opensearchproject/opensearch:latest`
- **实际版本**: 需要查询（见下方）
- **Distribution**: OpenSearch（非 Elasticsearch）

### OpenSearch Dashboards
- **镜像**: `opensearchproject/opensearch-dashboards:latest`
- **实际版本**: **3.4.0**（已确认）

### Security Analytics 插件
- **插件名称**: `opensearch-security-analytics`
- **状态**: ✅ 已安装并启用
- **功能**: 提供 Security Analytics 功能，包括 Findings 和 Correlation 分析

## 已安装的插件列表

根据 `opensearch-plugin list` 输出，当前安装的插件包括：

- opensearch-alerting
- opensearch-anomaly-detection
- opensearch-asynchronous-search
- opensearch-cross-cluster-replication
- opensearch-custom-codecs
- opensearch-flow-framework
- opensearch-geospatial
- opensearch-index-management
- opensearch-job-scheduler
- opensearch-knn
- opensearch-ltr
- opensearch-ml
- opensearch-neural-search
- opensearch-notifications
- opensearch-notifications-core
- opensearch-observability
- opensearch-performance-analyzer
- opensearch-reports-scheduler
- opensearch-search-relevance
- **opensearch-security** ✅
- **opensearch-security-analytics** ✅（关键插件）
- opensearch-skills
- opensearch-sql
- opensearch-system-templates
- opensearch-ubi
- query-insights

## 问题上下文

### 错误信息
```
[too_long_http_line_exception] An HTTP line is larger than 4096 bytes.
```

### 触发场景
- **位置**: OpenSearch Dashboards → Security Analytics → Findings 页面
- **操作**: 查询大量 findings（例如 160+ 个 finding IDs）
- **请求**: `GET /_plugins/_security_analytics/findings/_search?findingIds=...`
- **URL 长度**: ~6356 字符（超过 4096 字节限制）

### 当前修复方案
- **方法**: 通过 JVM 系统属性增加 HTTP 行长度限制
- **配置**: `OPENSEARCH_JAVA_OPTS=-Dhttp.max_initial_line_length=16k`
- **状态**: ✅ 已配置并生效

## 调研需求

基于以上信息，需要调研：

1. **官方 Issue/Bug Report**
   - OpenSearch GitHub: `opensearch-project/opensearch`
   - Security Analytics 插件: `opensearch-project/security-analytics`
   - 关键词: `too_long_http_line_exception`, `findings/_search`, `HTTP line too long`

2. **版本更新日志**
   - OpenSearch 3.4.0 及后续版本的 Release Notes
   - Security Analytics 插件的更新日志
   - 是否有相关修复或改进

3. **官方推荐方案**
   - 是否有配置项可以调整
   - 是否有插件层面的修复
   - 是否有 API 改进（例如支持 POST 请求）

4. **社区讨论**
   - OpenSearch Forum
   - GitHub Discussions
   - Stack Overflow

## 查询命令

### 查询 OpenSearch 版本
```bash
docker exec opensearch cat /usr/share/opensearch/package.json | grep version
```

### 查询 Security Analytics 插件版本
```bash
docker exec opensearch opensearch-plugin list | grep security-analytics
```

### 查询 OpenSearch API 信息
```bash
curl -k -u admin:OpenSearch@2024!Dev https://localhost:9200
```
