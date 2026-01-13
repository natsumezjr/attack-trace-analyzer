# 代码结构说明

本文档说明 `opensearch` 模块的代码组织结构。详细文件结构请参考 [README](../README.md)。

## 🎯 核心模块职责

## 🎯 核心模块职责

### `__init__.py` - 统一对外接口
- **职责**：统一导出所有公共API
- **原则**：外部代码只从这里导入，不直接导入内部模块
- **导出内容**：
  - 客户端操作函数
  - 索引管理函数
  - 存储功能函数
  - 数据分析函数
  - 索引映射常量

### `client.py` - 客户端配置和基础操作
- **职责**：
  - OpenSearch客户端配置（单例模式）
  - 基础CRUD操作（search、get、update、index、bulk_index）
  - 索引操作（exists、ensure、refresh）
- **关键函数**：
  - `get_client()` - 获取客户端单例
  - `search()` - 搜索文档
  - `bulk_index()` - 批量存储

### `index.py` - 索引管理
- **职责**：
  - 索引名称生成（带日期后缀）
  - 索引初始化
  - Token哈希
- **关键函数**：
  - `get_index_name()` - 生成索引名称
  - `initialize_indices()` - 初始化所有索引
  - `hash_token()` - Token哈希

### `storage.py` - 存储功能
- **职责**：
  - 数据路由（根据event.kind和event.dataset路由到对应索引）
  - 批量存储
  - 自动去重（基于event.id）
- **关键函数**：
  - `store_events()` - 存储事件（自动路由+去重）
  - `route_to_index()` - 路由到索引

### `analysis.py` - 数据分析
- **职责**：
  - Security Analytics检测调用
  - Findings转换（Security Analytics格式 → ECS格式）
  - 告警融合去重（Raw Findings → Canonical Findings）
- **关键函数**：
  - `run_security_analytics()` - 运行Security Analytics检测
  - `deduplicate_findings()` - 告警融合去重
  - `run_data_analysis()` - 完整数据分析流程
- **辅助函数**：
  - `generate_fingerprint()` - 生成告警指纹
  - `merge_findings()` - 合并findings
  - `_convert_security_analytics_finding_to_ecs()` - 格式转换
  - `_get_workflow_id_for_detector()` - 获取workflow ID
  - `_get_latest_findings_count()` - 获取findings数量

### `mappings.py` - 索引映射
- **职责**：定义所有索引的字段映射（类似数据库表结构）
- **映射定义**：
  - `ecs_events_mapping` - ECS事件映射
  - `raw_findings_mapping` - 原始告警映射
  - `canonical_findings_mapping` - 规范告警映射
  - `attack_chains_mapping` - 攻击链映射
  - `client_registry_mapping` - 客户端注册映射

### `trigger_lock.py` - 并发控制
- **职责**：防止Detector触发时的并发冲突
- **关键函数**：
  - `get_detector_lock()` - 获取detector锁
  - `register_trigger()` - 注册触发（单飞模式）
  - `complete_trigger()` - 标记触发完成

## 📋 代码组织原则

1. **单一职责**：每个模块只负责一个功能领域
2. **统一导入**：外部代码只从 `__init__.py` 导入
3. **常量提取**：API路径、配置项等提取为模块级常量
4. **类型提示**：所有函数都有完整的类型提示
5. **文档字符串**：所有公共函数都有详细的文档字符串

## 🔧 已完成的优化

- ✅ 修复类型提示错误
- ✅ 提取API路径和配置常量
- ✅ 统一API调用方式
- ✅ 代码清理和简化

## 📚 相关文档

- [API参考文档](./API_REFERENCE.md) - API使用说明
- [部署指南](./DEPLOYMENT.md) - 部署步骤
- [README](../README.md) - 模块概述
