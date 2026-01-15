# Correlation Rules 设计方案追踪文档

## 版本历史

| 版本 | 日期 | 方案 | 说明 |
|------|------|------|------|
| v1.0 | 2024-12 | 方案2：基于父进程特征 | 当前应用方案 |

---

## 当前方案：方案2 - 基于父进程特征（推荐）

### 方案概述

在提权检测的 Query1 和 Query3 中，除了匹配进程名/命令行中的提权关键词外，还匹配从可疑父进程（浏览器、邮件客户端）启动的进程。

### 查询条件结构

#### 必须满足的条件（AND）：
- `event.category:process`
- `event.action:process_start`
- `_exists_:host.id`

#### 至少满足一个的条件（OR）：
- **子进程名包含提权关键词**：
  - `process.name:*privilege*`
  - `process.name:*elevate*`
- **命令行包含提权关键词**：
  - `process.command_line:*runas*`
  - `process.command_line:*sudo*`
  - `process.command_line:*su *`
- **父进程是可疑进程**（新增）：
  - `process.parent.name:chrome.exe` - Chrome 浏览器
  - `process.parent.name:firefox.exe` - Firefox 浏览器
  - `process.parent.name:edge.exe` - Edge 浏览器
  - `process.parent.name:iexplore.exe` - Internet Explorer
  - `process.parent.name:outlook.exe` - Outlook 邮件客户端
  - `process.parent.name:thunderbird.exe` - Thunderbird 邮件客户端

### Query1 查询条件

**作用**：检测主机 A 上的提权行为（Privilege Escalation）

```python
"query": """event.category:process AND event.action:process_start AND (
  process.name:*privilege* OR 
  process.name:*elevate* OR 
  process.command_line:*runas* OR 
  process.command_line:*sudo* OR 
  process.command_line:*su * OR 
  process.parent.name:chrome.exe OR 
  process.parent.name:firefox.exe OR 
  process.parent.name:edge.exe OR 
  process.parent.name:iexplore.exe OR 
  process.parent.name:outlook.exe OR 
  process.parent.name:thunderbird.exe
) AND _exists_:host.id"""
```

### Query2 查询条件

**作用**：检测从主机 A 到主机 B 的远程连接事件（Remote Connect/Logon）

#### 必须满足的条件（AND）：
- `event.category:network` - 事件类型必须是网络事件
- `_exists_:source.ip` - 必须存在源 IP 地址字段
- `_exists_:destination.ip` - 必须存在目标 IP 地址字段
- `network.direction:outbound` - 网络方向必须是出站（从本机到外部）

```python
"query": "event.category:network AND _exists_:source.ip AND _exists_:destination.ip AND network.direction:outbound"
```

#### 匹配说明

**会被匹配的场景**：
- ✅ 主机 A (`source.ip: 192.168.1.10`) 连接到主机 B (`destination.ip: 192.168.1.20`)，方向为 `outbound`
- ✅ 主机 A 发起 SSH 连接、RDP 连接、SMB 连接等出站网络事件
- ✅ 任何包含源 IP 和目标 IP 的出站网络连接

**不会被匹配的场景**：
- ❌ 入站连接（`network.direction:inbound`）
- ❌ 缺少 `source.ip` 或 `destination.ip` 的网络事件
- ❌ 非网络类型的事件（如 `event.category:process`）

#### 注意事项

当前 Query2 只匹配**出站连接**。如果需要同时检测入站连接（例如从主机 B 的角度看是入站），可能需要：
- 添加 `network.direction:inbound` 条件
- 或创建额外的查询条件

**当前策略**：暂时保持只匹配出站连接，后续根据实际需求调整。

### Query3 查询条件

**作用**：检测主机 B 上的提权或远程执行行为（Privilege Escalation / Remote Execution）

#### 必须满足的条件（AND）：
- `_exists_:host.id` - 必须存在主机 ID 字段

#### 至少满足一个的条件（OR）：
- **进程创建事件**（提权尝试 + 父进程特征）：
  - `event.category:process AND event.action:process_start`
  - 且满足以下任一条件：
    - `process.name:*privilege*`
    - `process.name:*elevate*`
    - `process.command_line:*runas*`
    - `process.command_line:*sudo*`
    - `process.command_line:*su *`
    - `process.parent.name:chrome.exe` 等可疑父进程（与 Query1 相同）
- **认证事件**（远程登录）：
  - `event.category:authentication AND event.action:user_login`

```python
"query": """(event.category:process AND event.action:process_start AND (
  process.name:*privilege* OR 
  process.name:*elevate* OR 
  process.command_line:*runas* OR 
  process.command_line:*sudo* OR 
  process.command_line:*su * OR 
  process.parent.name:chrome.exe OR 
  process.parent.name:firefox.exe OR 
  process.parent.name:edge.exe OR 
  process.parent.name:iexplore.exe OR 
  process.parent.name:outlook.exe OR 
  process.parent.name:thunderbird.exe
)) OR (event.category:authentication AND event.action:user_login) AND _exists_:host.id"""
```

---

## 父进程特征说明

### 可疑父进程列表

| 父进程名 | 类型 | 说明 |
|---------|------|------|
| `chrome.exe` | 浏览器 | Chrome 浏览器 |
| `firefox.exe` | 浏览器 | Firefox 浏览器 |
| `edge.exe` | 浏览器 | Edge 浏览器 |
| `iexplore.exe` | 浏览器 | Internet Explorer |
| `outlook.exe` | 邮件客户端 | Outlook 邮件客户端 |
| `thunderbird.exe` | 邮件客户端 | Thunderbird 邮件客户端 |

### 为什么这些父进程被认为是可疑的？

#### 1. 攻击向量（Attack Vector）
- **浏览器启动提权工具**：通常表示通过网页/恶意链接触发的攻击
  - 用户点击恶意链接 → 浏览器下载并执行 → 提权工具启动
  - 这是常见的初始访问和提权攻击链
  
- **邮件客户端启动提权工具**：通常表示通过邮件附件/链接触发的攻击
  - 用户打开恶意邮件附件 → 邮件客户端执行 → 提权工具启动
  - 这是钓鱼攻击的常见模式

#### 2. 异常行为模式
- **正常情况**：提权工具通常由以下进程启动：
  - `explorer.exe` - 用户双击运行
  - `cmd.exe` - 命令行执行
  - `powershell.exe` - PowerShell 执行
  - `services.exe` - 系统服务启动
  
- **异常情况**：从浏览器/邮件客户端启动提权工具
  - 浏览器不应该直接启动提权工具
  - 邮件客户端不应该直接启动提权工具
  - 这通常表示恶意代码注入或用户交互式攻击

---

## 分级判断逻辑

### Level 1: 提权尝试（基于进程特征）
- **判断条件**：进程名或命令行包含提权关键词
- **置信度**：0.3-0.5
- **匹配阶段**：✅ Correlation 阶段（单条 event 即可判断）

### Level 2: 可疑提权行为（提权尝试 + 父进程异常）
- **判断条件**：
  - Level 1 的条件 +
  - 父进程是可疑进程（浏览器、邮件客户端等）
- **置信度**：0.5-0.7
- **匹配阶段**：✅ Correlation 阶段（单条 event 即可判断）
- **实现位置**：`classify_privilege_escalation_level()` 函数

### Level 3: 提权成功（提权尝试 + 后续高权限操作）
- **判断条件**：
  - Level 1/2 的条件 +
  - 后续有高权限操作事件（服务创建、计划任务创建、注册表修改等）
- **置信度**：0.8-1.0
- **匹配阶段**：⚠️ 部分在 Correlation 阶段，部分在后处理阶段
  - Correlation 阶段: 匹配提权尝试事件（Level 1/2）
  - 后处理阶段: 检查后续高权限操作事件，提升到 Level 3
- **实现位置**：
  - Correlation 阶段: `classify_privilege_escalation_level()` 函数
  - 后处理阶段: `enhance_privilege_level_with_followup_events()` 函数

---

## 匹配示例

### ✅ 会被匹配的场景

#### 场景1: 从浏览器启动普通进程（无提权关键词）
```
父进程: chrome.exe  ← 可疑父进程
子进程: cmd.exe
命令行: cmd.exe /c echo test
→ ✅ 匹配（因为父进程是可疑进程）
→ Level 2 (置信度 0.6)
```

#### 场景2: 从邮件客户端启动提权工具
```
父进程: outlook.exe  ← 可疑父进程
子进程: runas.exe
命令行: runas /user:admin cmd.exe
→ ✅ 匹配（父进程可疑 + 有提权关键词）
→ Level 2 (置信度 0.6)
```

#### 场景3: 正常父进程 + 提权关键词
```
父进程: explorer.exe  ← 正常父进程
子进程: privilege-escalator.exe
命令行: privilege-escalator.exe --elevate
→ ✅ 匹配（有提权关键词）
→ Level 1 (置信度 0.4)
```

### ❌ 不会被匹配的场景

#### 场景1: 正常父进程 + 普通进程（无提权关键词）
```
父进程: explorer.exe  ← 正常父进程
子进程: notepad.exe
命令行: notepad.exe
→ ❌ 不匹配（没有提权关键词，父进程也不可疑）
```

#### 场景2: 事件类型不是进程创建
```
父进程: chrome.exe
子进程: cmd.exe
event.category: network  ← 不是 process
→ ❌ 不匹配（事件类型不对）
```

---

## 方案优势

1. **提高检测覆盖率**：
   - 能够检测到从浏览器/邮件客户端启动的恶意进程，即使进程名本身没有提权关键词
   - 例如：从 Chrome 启动的 `cmd.exe` 或 `powershell.exe` 也会被检测

2. **降低误报率**：
   - 相比方案1（检测所有进程创建），方案2更精准
   - 只关注可疑父进程，而不是所有父进程

3. **保持灵活性**：
   - 仍然匹配有提权关键词的进程（即使父进程正常）
   - 两套检测逻辑并行工作，互不干扰

---

## 关联逻辑实现

### 关联方式

由于 OpenSearch Security Analytics API 的 correlation 功能只在 `raw-findings-*` 索引中查找，而我们的 correlation rule 配置在 `ecs-events-*` 索引中匹配 events，因此**强制使用手动应用规则模式**。

### 关联条件（3个查询的关联）

#### Query1 ↔ Query2（主机A上的提权事件 ↔ 从A到B的网络连接）
- **条件1**：Query1 的事件在主机A上，Query2 的源主机也是主机A（`host_1 == host_2`）
- **条件2**：用户相同（增强关联性）
- **说明**：Query1 的提权事件没有网络IP信息，因此基于主机ID和用户名称关联

#### Query2 ↔ Query3（从A到B的网络连接 ↔ 主机B上的提权事件）
- **条件1**：Query2 的 `destination.ip` 对应主机B
- **条件2**：Query3 的事件在主机B上（`host_3`）
- **条件3**：Query2 的源主机与 Query3 的主机不同（`host_2 != host_3`）
- **条件4**：用户相同（增强关联性）
- **说明**：Query3 的提权事件没有网络IP信息，因此基于主机ID和用户名称关联

### 关联逻辑特点

1. **不依赖IP字段**：
   - 提权事件（Query1 和 Query3）没有网络IP信息
   - 关联逻辑基于主机ID和用户名称

2. **时间窗口**：
   - 所有事件必须在 correlation rule 配置的时间窗口内（默认30分钟）

3. **用户一致性**：
   - 三个事件的用户应该相同（如果存在用户信息）
   - 如果用户信息缺失，也允许关联（基于主机）

## 实现位置

### 代码文件
- `backend/app/services/opensearch/analysis.py`
  - `create_lateral_movement_correlation_rule()` - Query1 和 Query3 的查询条件
  - `classify_privilege_escalation_level()` - 分级判断逻辑
  - `apply_correlation_rule_manually()` - 手动应用规则，在 events 索引中查询并关联
  - `aggregate_correlation_chains()` - 聚合关联链

### 测试数据生成
- `backend/app/services/opensearch/scripts/create_correlation_test_data.py` - 生成横向移动攻击链的测试 events 数据

### 相关文档
- `backend/app/services/opensearch/scripts/explain_parent_process_features.py` - 父进程特征说明脚本
- `backend/app/services/opensearch/scripts/explain_privilege_levels.py` - 分级判断说明脚本

---

## 后续优化方向

1. **扩展可疑父进程列表**：
   - 根据实际攻击案例，添加更多可疑父进程
   - 例如：`winword.exe`（Word）、`excel.exe`（Excel）等办公软件

2. **动态父进程特征**：
   - 基于历史数据，动态识别异常父进程
   - 例如：某个进程通常由 `explorer.exe` 启动，但突然从 `chrome.exe` 启动

3. **跨平台支持**：
   - 当前主要针对 Windows 平台
   - 后续可以添加 Linux/Mac 的可疑父进程特征

---

## 更新日志

### 2024-12-XX
- ✅ 应用方案2：基于父进程特征
- ✅ 更新 Query1 和 Query3 的查询条件
- ✅ 创建方案追踪文档
- ✅ 修复关联逻辑：从基于IP匹配改为基于主机ID和用户名称匹配
- ✅ 强制使用手动应用规则模式（在 events 索引中查询，而不是依赖 OpenSearch API）
- ✅ 创建测试数据生成脚本（生成 events 数据而非 findings 数据）
