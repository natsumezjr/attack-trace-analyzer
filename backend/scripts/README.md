# Backend Scripts

Backend 脚本目录，包含各种辅助工具和测试脚本。

## 目录结构

```
backend/scripts/
├── README.md                              # 本文件
├── fetch_mitre_attack_cti.sh              # MITRE ATT&CK CTI 数据下载脚本
└── opensearch/                            # OpenSearch 相关脚本
    ├── clear_findings_data.py             # Findings 数据清理工具
    ├── generate_security_test_events.py   # 测试事件生成器
    ├── test_findings_conversion.py        # Findings 转换和存储测试
    ├── test_findings_deduplication.py     # 告警去重测试工具
    ├── test_full_analysis_flow.py         # 完整分析流程测试
    ├── test_security_analytics_flow.py    # Security Analytics 完整测试流程
    └── test_storage_with_cleanup.py       # 存储测试（含数据清理）
```

## 脚本说明

### 1. MITRE ATT&CT CTI 数据下载

**文件**: `fetch_mitre_attack_cti.sh`

**功能**:
- 从 MITRE ATT&CK 官方仓库下载 Enterprise CTI (STIX 2.1) 数据包
- 用于离线 TTP (Tactics, Techniques, and Procedures) 相似度分析
- 自动验证下载的文件格式和完整性

**使用方式**:
```bash
# 基本用法（使用默认路径）
cd backend
./scripts/fetch_mitre_attack_cti.sh

# 强制重新下载
./scripts/fetch_mitre_attack_cti.sh --force

# 自定义输出路径
./scripts/fetch_mitre_attack_cti.sh /custom/path/enterprise-attack.json
```

**输出路径**: `backend/app/services/ttp_similarity/cti/enterprise-attack.json`

---

### 2. OpenSearch 相关脚本

#### 2.1 数据清理工具

**文件**: `opensearch/clear_findings_data.py`

**功能**:
- 清除 OpenSearch 中的 raw-findings 和 canonical-findings 索引数据
- 用于测试前清空已有数据
- 删除前会显示数据条数并要求确认

**使用方式**:
```bash
cd backend
uv run python scripts/opensearch/clear_findings_data.py
```

---

#### 2.2 测试事件生成器

**文件**: `opensearch/generate_security_test_events.py`

**功能**:
- 生成符合 ECS 格式的测试安全事件
- 包括可疑事件和正常事件，可以触发检测规则
- 生成的事件类型：
  - DNS 查询事件（包括可疑域名）
  - 进程创建事件（包括可疑命令）

**使用方式**:
```bash
cd backend
uv run python scripts/opensearch/generate_security_test_events.py
```

---

#### 2.3 Findings 转换和存储测试

**文件**: `opensearch/test_findings_conversion.py`

**功能**:
- 测试 findings 的转换和存储功能
- 验证从 Security Analytics 检测结果到存储的完整流程
- 显示转换和存储结果统计

**使用方式**:
```bash
cd backend
uv run python scripts/opensearch/test_findings_conversion.py
```

---

#### 2.4 告警去重测试工具

**文件**: `opensearch/test_findings_deduplication.py`

**功能**:
- 测试告警去重功能
- 将 raw-findings 合并为 canonical-findings
- 显示去重结果统计

**使用方式**:
```bash
cd backend
uv run python scripts/opensearch/test_findings_deduplication.py
```

---

#### 2.5 存储测试（含数据清理）

**文件**: `opensearch/test_storage_with_cleanup.py`

**功能**:
- 测试 findings 存储功能
- 先清除已有数据，再运行检测和存储
- 验证完整的存储流程

**使用方式**:
```bash
cd backend
uv run python scripts/opensearch/test_storage_with_cleanup.py
```

---

#### 2.6 完整分析流程测试

**文件**: `opensearch/test_full_analysis_flow.py`

**功能**:
- 测试完整的安全分析流程
- 包括检测和去重两个步骤
- 验证从事件到 canonical findings 的完整流程

**使用方式**:
```bash
cd backend
uv run python scripts/opensearch/test_full_analysis_flow.py
```

---

#### 2.7 Security Analytics 完整测试流程

**文件**: `opensearch/test_security_analytics_flow.py`

**功能**:
- 完整测试 Security Analytics 流程
- 包括索引、规则、detector、检测和去重
- 最全面的 Security Analytics 测试脚本

**测试流程**:
1. 检查索引是否创建
2. 检查 Sigma 规则是否导入
3. 检查 detector 是否配置
4. 运行 Security Analytics 检测
5. 运行告警去重
6. 验证 findings 索引
7. 显示测试总结

**使用方式**:
```bash
cd backend
uv run python scripts/opensearch/test_security_analytics_flow.py
```

**环境要求**:
- OpenSearch 服务运行中
- Security Analytics 插件已安装
- Sigma 规则已导入
- Detector 已创建
- 事件数据已存在

---

## 完整测试流程示例

### 场景1：首次测试 Security Analytics

```bash
# 1. 下载 MITRE ATT&CK CTI 数据
cd backend
./scripts/fetch_mitre_attack_cti.sh

# 2. 生成测试事件
uv run python scripts/opensearch/generate_security_test_events.py

# 3. 运行完整测试流程
uv run python scripts/opensearch/test_security_analytics_flow.py
```

### 场景2：反复测试存储功能

```bash
cd backend

# 1. 清除已有数据
uv run python scripts/opensearch/clear_findings_data.py

# 2. 运行存储测试（会自动清除数据）
uv run python scripts/opensearch/test_storage_with_cleanup.py
```

### 场景3：测试完整分析流程

```bash
cd backend

# 1. 生成测试事件
uv run python scripts/opensearch/generate_security_test_events.py

# 2. 运行完整分析流程
uv run python scripts/opensearch/test_full_analysis_flow.py

# 3. 单独测试告警去重
uv run python scripts/opensearch/test_findings_deduplication.py
```

---

## 环境要求

所有脚本都需要以下环境：

### 通用要求
- Python 3.12+
- `uv` 包管理器
- 已配置环境变量（参考 `backend/.env.example`）

### OpenSearch 相关脚本要求
- OpenSearch 服务运行中（通常通过 `docker-compose up` 启动）
- Security Analytics 插件已安装
- 已创建相关索引和 detector

### 依赖检查

```bash
# 检查 Python 版本
python3 --version

# 检查 uv 是否安装
uv --version

# 检查 OpenSearch 是否运行
curl http://localhost:9200
```

---

## 故障排查

### 问题1：无法连接到 OpenSearch

**错误信息**: `ConnectionError` 或 `Connection refused`

**解决方案**:
```bash
# 检查 OpenSearch 是否运行
docker ps | grep opensearch

# 启动 OpenSearch
cd backend
docker-compose up -d
```

### 问题2：没有检测到 findings

**可能原因**:
1. Security Analytics 还在扫描中（需要等待 1-2 分钟）
2. 测试数据没有触发规则
3. 规则配置需要调整

**解决方案**:
```bash
# 生成更多测试数据
uv run python scripts/opensearch/generate_security_test_events.py

# 等待一段时间后重新运行检测
uv run python scripts/opensearch/test_security_analytics_flow.py
```

### 问题3：MITRE ATT&CK 数据下载失败

**错误信息**: `curl` 或网络错误

**解决方案**:
```bash
# 检查网络连接
curl -I https://raw.githubusercontent.com

# 使用代理（如果需要）
export https_proxy=http://your-proxy:port
./scripts/fetch_mitre_attack_cti.sh
```

---

## 相关文档

- [Backend README](../README.md)
- [OpenSearch 测试文档](../tests/opensearch/README.md)
- [环境配置指南](../.env.example)

---

## 维护说明

### 添加新脚本

1. 将脚本放到相应的子目录
2. 添加详细的文档注释（参考现有脚本）
3. 更新本 README 文件
4. 确保脚本可执行（`chmod +x`）

### 更新现有脚本

1. 保持注释与代码同步
2. 更新使用示例
3. 测试脚本功能
4. 更新相关文档

---

## 贡献指南

如果你需要添加新的辅助脚本或测试工具：

1. 遵循现有的命名规范
2. 添加详细的文档注释
3. 包含使用示例和故障排查信息
4. 确保脚本跨平台兼容（Windows/macOS/Linux）
5. 更新本 README 文件

---

**最后更新**: 2026-01-14
**维护者**: Zhang Tianhua
