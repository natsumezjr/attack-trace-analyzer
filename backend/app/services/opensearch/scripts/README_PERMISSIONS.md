# OpenSearch Alerting 权限配置指南

## 问题说明

执行 Security Analytics workflow 需要以下权限：
- 读取 alerting 系统索引（`.opensearch-alerting-config` 等）
- 执行 monitor/workflow
- 查询业务索引（`ecs-events-*`）

## 快速配置（推荐）

### 方法1：使用脚本自动配置

```bash
# 1. 检查当前权限
python check_alerting_permissions.py

# 2. 配置权限（需要admin账号）
python setup_alerting_permissions.py --username <你的用户名>

# 3. 重新测试
python test_step7_security_analytics.py --trigger-scan
```

### 方法2：通过 Dashboards UI

1. 登录 OpenSearch Dashboards
2. 进入 Security → Roles
3. 创建新角色或编辑现有角色，添加以下权限：
   - **Cluster Permissions**: `cluster:admin/opensearch/alerting/*`
   - **Index Permissions**: 
     - 索引: `.opensearch-alerting-config`, `.opendistro-alerting-config`, `.opensearch-alerting-queries`
     - 权限: `read`, `search`, `indices:data/read/get`
   - **Index Permissions**:
     - 索引: `ecs-events-*`
     - 权限: `read`, `search`
4. 将用户映射到该角色

### 方法3：使用 Security REST API（需要admin权限）

```bash
# 创建角色
curl -X PUT "https://your-opensearch:9200/_plugins/_security/api/roles/sa_runner" \
  -H "Content-Type: application/json" \
  -u admin:admin \
  -d @roles/sa_runner_role.json

# 映射用户
curl -X PUT "https://your-opensearch:9200/_plugins/_security/api/rolesmapping/sa_runner" \
  -H "Content-Type: application/json" \
  -u admin:admin \
  -d '{
    "users": ["your_username"]
  }'
```

## 权限说明

### 最小权限配置

角色配置模板见：`roles/sa_runner_role.json`

**必需权限：**
1. **Cluster Permissions**:
   - `cluster:admin/opensearch/alerting/*` - alerting插件管理权限
   - `cluster:monitor/*` - 监控权限

2. **Index Permissions**:
   - `.opensearch-alerting-config` / `.opendistro-alerting-config` - alerting配置索引
   - `.opensearch-alerting-queries` - alerting查询索引
   - `ecs-events-*` - 业务数据索引
   - 权限: `read`, `search`, `indices:data/read/get`, `indices:data/read/search`

## 验证权限

运行检查脚本：

```bash
python check_alerting_permissions.py
```

如果所有检查通过，说明权限配置正确。

## 故障排查

### 如果 GET monitor 配置失败

错误：`500 alerting_exception ... indices:data/read/get`

**原因**：缺少读取 alerting 系统索引的权限

**解决**：
1. 确保角色有对 `.opensearch-alerting-config` 的 `read` 和 `indices:data/read/get` 权限
2. 确保用户已映射到该角色
3. 重新连接 OpenSearch 以应用新权限

### 如果 execute 失败但 GET 成功

**原因**：可能是执行时的其他权限问题（如业务索引查询权限）

**解决**：
1. 检查是否有对 `ecs-events-*` 的查询权限
2. 检查是否有 `cluster:admin/opensearch/alerting/*` 权限

## 注意事项

1. **权限生效**：配置权限后，需要重新连接 OpenSearch 才能生效
2. **最小权限原则**：建议使用最小权限配置，而不是直接使用 `alerting_full_access`
3. **测试环境**：建议先在测试环境验证权限配置
