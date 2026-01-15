# OpenSearch OOM问题修复指南

## 问题分析

根据日志分析，OpenSearch节点因为JVM堆内存溢出（OOM）而崩溃：

1. **JVM堆内存太小**：当前配置只有512MB（`-Xms512m -Xmx512m`）
2. **GC频繁且耗时**：说明内存压力大，接近OOM
3. **可能的原因**：
   - 批量写入2100个events时内存压力过大
   - 每次写入后都refresh索引，增加内存压力
   - 可能有wildcard/query_string查询导致内存问题

## 修复方案

### 1. 增加JVM堆内存（最重要）

**修改 `backend/docker-compose.yml`**：

```yaml
environment:
  - OPENSEARCH_JAVA_OPTS=${OPENSEARCH_JAVA_OPTS:--Xms2g -Xmx2g}
```

**或者通过环境变量设置**：

```bash
export OPENSEARCH_JAVA_OPTS="-Xms2g -Xmx2g"
```

**建议值**：
- 开发环境：`-Xms2g -Xmx2g`（2GB）
- 生产环境：机器内存的50%，但不超过32GB

### 2. 优化批量写入

**已修改 `backend/app/services/opensearch/storage.py`**：
- 移除了每次写入后的`refresh_index`调用
- 减少refresh频率，降低内存压力

**使用优化的批量写入脚本**：
```python
from app.services.opensearch.scripts.optimize_bulk_write import store_events_optimized
store_events_optimized(events, batch_size=300, refresh_after=True)
```

### 3. 检查集群健康状态

运行健康检查脚本：
```bash
cd backend
uv run python app/services/opensearch/scripts/check_opensearch_health.py
```

### 4. 重启OpenSearch容器

修改配置后需要重启容器：
```bash
cd backend
docker compose restart opensearch
```

## 验证修复

1. **检查JVM配置**：
   ```bash
   docker exec opensearch ps aux | grep java
   # 应该看到 -Xms2g -Xmx2g
   ```

2. **检查集群健康**：
   ```bash
   curl -k -u admin:OpenSearch@2024!Dev https://localhost:9200/_cluster/health
   ```

3. **检查JVM内存使用**：
   ```bash
   curl -k -u admin:OpenSearch@2024!Dev https://localhost:9200/_nodes/stats/jvm?pretty
   ```

## 预防措施

1. **分批写入**：每次写入不超过500个events
2. **减少refresh频率**：批量写入时临时设置`refresh_interval=30s`
3. **避免wildcard查询**：检查monitors和workflows，避免使用`*xxx`这种leading wildcard
4. **监控内存使用**：定期检查JVM内存使用率，超过75%时需要注意

## 相关文件

- `backend/docker-compose.yml` - JVM配置
- `backend/app/services/opensearch/storage.py` - 批量写入逻辑
- `backend/app/services/opensearch/scripts/optimize_bulk_write.py` - 优化的批量写入
- `backend/app/services/opensearch/scripts/check_opensearch_health.py` - 健康检查
