# OpenSearch 权限诊断总结

## 当前状态

### 1. 用户身份确认
- **用户名**: `admin`
- **Backend roles**: `['admin']`
- **Roles**: `['sa_runner', 'own_index', 'all_access']`

✅ **确认**: 代码确实使用的是 `admin` 用户，并且有 `all_access` 角色。

### 2. all_access 角色配置
```json
{
  "cluster_permissions": ["*"],
  "index_permissions": [{
    "index_patterns": ["*"],
    "allowed_actions": ["*"]
  }]
}
```

✅ **理论上**: `all_access` 应该拥有所有权限，包括：
- 所有集群权限（包括 alerting 相关）
- 所有索引访问权限（包括系统索引）
- 所有索引操作权限（包括 `indices:data/read/get`）

### 3. 实际遇到的问题

**错误信息**:
```
TransportError(500, 'alerting_exception', '[indices:data/read/get[s]]')
```

**发生位置**:
- `GET /_plugins/_alerting/monitors/{workflow_id}` - 读取 monitor 配置
- `POST /_plugins/_alerting/monitors/{workflow_id}/_execute` - 执行 workflow

## 可能的原因

### 原因1: Alerting 插件内部权限检查
Alerting 插件可能有自己的权限检查机制，绕过了 OpenSearch Security 的标准权限检查。即使 `all_access` 角色理论上拥有所有权限，Alerting 插件内部可能仍然需要特定的权限配置。

### 原因2: 系统索引的特殊限制
某些 OpenSearch 版本可能对系统索引（如 `.opendistro-alerting-config`）有特殊的安全限制，即使 `all_access` 也可能被限制。

### 原因3: OpenSearch 版本或配置问题
可能是 OpenSearch 版本特定的 bug 或配置问题。

## 解决方案

### 方案1: 跳过 GET 检查，直接执行（已实现）
修改 `_execute_workflow_manually` 函数，即使 GET monitor 配置失败，也继续尝试执行 workflow。因为：
- `execute` API 的权限检查可能独立于 `GET` API
- 某些版本中，`execute` 可能不需要读取完整配置

### 方案2: 使用 Fallback 机制（已实现）
如果 `execute` API 失败，代码会自动 fallback 到：
1. `disable/enable detector` - 强制触发扫描
2. 临时缩短 schedule - 等待下次扫描

### 方案3: 显式配置权限（可选）
虽然理论上 `all_access` 应该足够，但如果问题持续，可以尝试：
1. 为 `admin` 用户显式添加 `sa_runner` 角色（已添加）
2. 检查 OpenSearch Security 配置，确保没有额外的限制
3. 检查 Alerting 插件的配置

## 测试建议

1. **直接测试 execute API**:
   ```bash
   cd backend/app/services/opensearch/scripts
   uv run python test_step8_trigger_workflow.py
   ```

2. **检查权限**:
   ```bash
   uv run python check_current_user_identity.py
   uv run python check_all_access_role.py
   ```

3. **详细诊断**:
   ```bash
   uv run python test_monitor_access.py --workflow-id TeBJt5sBYd8aacU-nv8J
   ```

## 下一步

1. ✅ 已确认用户身份和角色配置
2. ✅ 已修改代码，跳过 GET 检查，直接尝试 execute
3. ⏳ 等待测试结果，确认 execute API 是否成功
4. ⏳ 如果 execute 仍然失败，使用 fallback 机制（disable/enable）

## 注意事项

- `all_access` 角色是保留角色（reserved），不能直接修改
- 如果问题持续，可能需要检查 OpenSearch 的版本和配置
- Alerting 插件的权限检查可能与 OpenSearch Security 的标准检查不同
