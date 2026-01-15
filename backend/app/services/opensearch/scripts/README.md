# 脚本工具目录

本目录包含用于配置和管理 OpenSearch Security Analytics 的脚本工具。

## 📋 脚本列表

### `import_sigma_rules.py` - Sigma规则导入工具

**功能**：将Sigma规则导入到OpenSearch Security Analytics

**使用方法**：
```bash
cd backend/opensearch/scripts

# 查看可用的规则类别
python import_sigma_rules.py --list

# 导入特定类别
python import_sigma_rules.py --category dns
python import_sigma_rules.py --category windows

# 导入特定ATT&CK技术的规则
python import_sigma_rules.py --attack-id T1055

# 预览将要导入的规则（不实际导入）
python import_sigma_rules.py --category dns --dry-run
```

**详细说明**：参考主文档 [README](../README.md)

---

### `setup_security_analytics.py` - Security Analytics配置工具

**功能**：自动配置OpenSearch Security Analytics，创建默认的detector

**使用方法**：
```bash
cd backend/opensearch/scripts
python setup_security_analytics.py
```

**功能**：
1. 检查Security Analytics插件是否可用
2. 检查索引是否存在（不存在则创建）
3. 获取预打包规则
4. 创建Detector（如果不存在）
5. 验证Detector状态

**详细说明**：参考 [部署指南](../docs/DEPLOYMENT.md)

---

### `test_import_rules.py` - 规则导入测试工具

**功能**：测试规则导入功能，验证findings生成

**使用方法**：
```bash
cd backend/opensearch/scripts
python test_import_rules.py
```

**功能**：
1. 验证规则是否已导入
2. 检查detector状态
3. 验证findings生成

---

## 📚 相关文档

- [部署指南](../docs/DEPLOYMENT.md) - 完整的部署步骤
- [API参考文档](../docs/API_REFERENCE.md) - API使用说明
- [进度总结](../docs/进度总结.md) - 功能实现进度
