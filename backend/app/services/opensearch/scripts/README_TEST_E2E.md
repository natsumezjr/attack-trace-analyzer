# 端到端测试说明

## 测试脚本：`test_e2e_analysis.py`

这个脚本用于从Docker容器启动开始，完整测试analysis模块的功能。

## 功能

1. **检查并启动Docker容器**
   - 检查Docker是否运行
   - 检查OpenSearch容器是否运行
   - 如果未运行，自动启动

2. **等待OpenSearch就绪**
   - 等待OpenSearch集群健康检查通过
   - 最多等待120秒

3. **测试规则和detector自动设置**
   - 调用 `_check_and_setup_rules_detectors()` 函数
   - 验证自动导入规则和创建detector功能

4. **测试威胁信息提取**
   - 使用测试finding验证ATT&CK Tactic提取功能
   - 验证Technique ID到Tactic ID的映射

5. **测试完整分析流程**
   - 调用 `run_data_analysis()` 函数
   - 验证检测和去重功能
   - 检查索引变化

6. **检查findings中的tactic提取**
   - 查询Raw Findings索引
   - 统计tactic提取情况

## 使用方法

### 前置条件

1. 确保Docker已安装并运行
2. 确保有 `docker-compose.yml` 文件在 `backend/` 目录

### 运行测试

```bash
# 进入scripts目录
cd backend/app/services/opensearch/scripts

# 运行测试（需要Python环境）
python test_e2e_analysis.py

# 或者使用uv（如果项目使用uv）
uv run python test_e2e_analysis.py
```

### 环境变量

脚本会自动设置默认的OpenSearch密码：
- `OPENSEARCH_INITIAL_ADMIN_PASSWORD` (默认: `OpenSearch@2024!Dev`)

如果需要自定义，可以设置环境变量：
```bash
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="your-password"
python test_e2e_analysis.py
```

## 预期输出

测试脚本会输出详细的步骤信息和结果：

```
================================================================================
端到端测试：从Docker容器启动到验证analysis函数
================================================================================

[OK] OpenSearch容器已在运行

[2] 等待OpenSearch就绪（最多等待120秒）...
[OK] OpenSearch已就绪，集群状态: green

================================================================================
[3] 测试规则和detector自动设置功能
================================================================================
[INFO] 规则和detector已就绪（规则: 100, Detector: 5）

================================================================================
[4] 测试威胁信息提取（ATT&CK Tactic）
================================================================================
[OK] Tactic提取正确！

================================================================================
[5] 测试运行完整分析流程（run_data_analysis）
================================================================================
[OK] 生成了Canonical Findings

================================================================================
[6] 检查findings中的tactic提取情况
================================================================================
[OK] 所有findings的tactic都已正确提取！

================================================================================
测试完成
================================================================================
```

## 故障排查

### Docker未运行
```
[ERROR] Docker未运行，请先启动Docker
```
**解决方案**：启动Docker Desktop或Docker服务

### OpenSearch容器启动失败
```
[ERROR] 无法启动OpenSearch容器
```
**解决方案**：
- 检查 `docker-compose.yml` 文件是否存在
- 检查端口9200是否被占用
- 查看Docker日志：`docker logs opensearch`

### OpenSearch未就绪
```
[ERROR] OpenSearch在120秒内未就绪
```
**解决方案**：
- 检查OpenSearch容器日志：`docker logs opensearch`
- 增加等待时间（修改脚本中的 `max_wait_seconds` 参数）
- 检查OpenSearch健康状态：`curl -k -u admin:password https://localhost:9200/_cluster/health`

### 规则和detector未设置
```
[WARNING] 规则或detector未就绪（可能需要手动设置）
```
**解决方案**：
- 手动运行导入脚本：
  ```bash
  cd backend/app/services/opensearch/scripts
  uv run python import_sigma_rules.py --auto
  uv run python setup_security_analytics.py --multiple
  ```

## 注意事项

1. **首次运行**：首次运行可能需要较长时间，因为需要：
   - 启动Docker容器
   - 等待OpenSearch就绪
   - 导入规则和创建detector

2. **网络要求**：脚本需要访问 `https://localhost:9200`，确保端口未被占用

3. **SSL证书**：脚本会忽略SSL证书验证（仅用于开发环境）

4. **测试数据**：如果没有实际的检测数据，某些测试可能显示"没有findings"，这是正常的
