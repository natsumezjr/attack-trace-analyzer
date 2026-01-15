# Correlation Rules 设计方案追踪文档

## 版本历史

| 版本 | 日期 | 方案 | 说明 |
|------|------|------|------|
| v1.0 | 2024-12 | 方案2：基于父进程特征 | 初始方案 |
| v1.1 | 2026-01-15 | 方案2 + 最近匹配优化 | **当前应用方案** - 优化关联逻辑，避免笛卡尔积问题 |

---

## 当前方案：方案2 - 基于父进程特征 + 最近匹配优化（推荐）

### 方案概述

在提权检测的 Query1 和 Query3 中，除了匹配进程名/命令行中的提权关键词外，还匹配从可疑父进程（浏览器、邮件客户端）启动的进程。

**最新优化（2026-01-15）**：
- 采用"最近匹配"策略优化关联逻辑，避免笛卡尔积问题
- 关联数量从 80 个优化到 4 个（等于 Query2 事件数量）
- 添加时间顺序检查和去重逻辑

### 查询条件结构

#### 必须满足的条件（AND）：
- `event.category:process`
- `event.action:process_start`
- `_exists_:host.name`

#### 至少满足一个的条件（OR）：
- **子进程名包含提权关键词**：
  - `process.name:*privilege*`
  - `process.name:*elevate*`
- **命令行包含提权关键词**：
  - `process.command_line:*runas*`
  - `process.command_line:*sudo*`
  - `process.command_line:*su *`
- **父进程是可疑进程**（Linux/Unix 版本）：
  - `process.parent.name:chrome` - Chrome 浏览器（Linux）
  - `process.parent.name:firefox` - Firefox 浏览器（Linux）
  - `process.parent.name:chromium` - Chromium 浏览器（Linux）
  - `process.parent.name:thunderbird` - Thunderbird 邮件客户端（Linux）
  - `process.parent.name:evolution` - Evolution 邮件客户端（Linux）
  - `process.parent.name:geary` - Geary 邮件客户端（Linux）
  
  **注意**：已移除 Windows 进程名（.exe 后缀），因为系统现在只支持 Linux/Unix 环境。

### Query1 查询条件

**作用**：检测主机 A 上的提权行为（Privilege Escalation）

```python
"query": """event.category:process AND event.action:process_start AND (
  process.name:*privilege* OR 
  process.name:*elevate* OR 
  process.command_line:*runas* OR 
  process.command_line:*sudo* OR 
  process.command_line:*su * OR 
  process.parent.name:chrome OR 
  process.parent.name:firefox OR 
  process.parent.name:chromium OR 
  process.parent.name:thunderbird OR 
  process.parent.name:evolution OR 
  process.parent.name:geary
) AND _exists_:host.name"""
```

### Query2 查询条件

**作用**：检测从主机 A 到主机 B 的远程连接事件（Remote Connect/Logon）

#### 必须满足的条件（AND）：
- `event.category:network` - 事件类型必须是网络事件
- `_exists_:source.ip` - 必须存在源 IP 地址字段
- `_exists_:destination.ip` - 必须存在目标 IP 地址字段
- `_exists_:host.name` - 必须存在主机名称字段（用于关联逻辑：`host_1 == host_2` 和 `host_2 != host_3`）
- `network.direction:outbound` - 网络方向必须是出站（从本机到外部）

#### 排除的条件（NOT）：
- `NOT (destination.port:80 OR destination.port:443 OR destination.port:8080 OR destination.port:8443)` - 排除 HTTP/HTTPS 连接
  - **原因**：横向移动通常不使用 HTTP 协议
  - **横向移动常用协议**：
    - RDP (3389) - 远程桌面
    - SSH (22) - 安全 Shell
    - SMB (445) - 文件共享
    - WinRM (5985, 5986) - Windows 远程管理
    - Telnet (23) - 远程登录
    - VNC (5900-5909) - 远程桌面
    - 其他管理端口

```python
"query": "event.category:network AND _exists_:source.ip AND _exists_:destination.ip AND _exists_:host.name AND network.direction:outbound AND NOT (destination.port:80 OR destination.port:443 OR destination.port:8080 OR destination.port:8443)"
```

#### 为什么必须是出站（outbound）？

**原因分析**：

1. **关联逻辑的限制**：
   - Query1 ↔ Query2 的关联条件要求：`host_1 == host_2`（Query1 的事件在主机A上，Query2 的源主机也必须是主机A）
   - 这意味着 Query2 的网络连接事件**必须在主机A上采集**
   - 从主机A的角度看，A→B 的连接方向是 `outbound`

2. **三个实体的匹配**：
   - **三个事件**：Query1（主机A提权）、Query2（A→B网络连接）、Query3（主机B提权）
   - **三个实体**：主机A、主机B、用户
   - **关联逻辑**：
     - Query1 ↔ Query2：`host_1 == host_2`（同一主机A）+ 用户相同
     - Query2 ↔ Query3：`host_3 != host_2`（不同主机，B≠A）+ `destination.ip` 对应主机B + 用户相同
   - ✅ **结论**：当前设计可以正确匹配到三个实体（主机A、主机B、用户），但前提是 Query2 的事件必须在主机A上采集

3. **当前限制**：
   - ❌ 如果网络连接事件在主机B上采集（从B的角度看是 `inbound`），则不会被匹配
   - ❌ 如果事件在中间设备（如防火墙、交换机）上采集，可能无法正确关联

#### 匹配说明

**会被匹配的场景**：
- ✅ 主机 A (`source.ip: 192.168.1.10`) 连接到主机 B (`destination.ip: 192.168.1.20`)，方向为 `outbound`，且事件在主机A上采集
- ✅ 主机 A 发起 SSH 连接（端口22）、RDP 连接（端口3389）、SMB 连接（端口445）等出站网络事件（在主机A上采集）
- ✅ WinRM 连接（端口5985、5986）、Telnet 连接（端口23）、VNC 连接（端口5900-5909）等管理协议
- ✅ 任何包含源 IP 和目标 IP 的出站网络连接（在源主机上采集），**但排除 HTTP/HTTPS**

**不会被匹配的场景**：
- ❌ 入站连接（`network.direction:inbound`）- 即使是从A到B的连接，如果在主机B上采集也不会被匹配
- ❌ HTTP/HTTPS 连接（端口80、443、8080、8443）- 横向移动通常不使用 HTTP 协议
- ❌ 缺少 `source.ip` 或 `destination.ip` 的网络事件
- ❌ 非网络类型的事件（如 `event.category:process`）
- ❌ 在主机B上采集的A→B连接事件（方向为 `inbound`）

#### 注意事项

**当前策略**：只匹配出站连接（`outbound`），且要求事件在源主机（主机A）上采集。

**潜在问题**：
- 如果网络连接事件在目标主机（主机B）上采集，会被漏掉
- 如果事件在中间设备上采集，可能无法正确关联到源主机

**后续优化方向**：
- 方案1：同时匹配 `outbound` 和 `inbound`，但需要调整关联逻辑：
  - 对于 `outbound`：`host_1 == host_2`（在主机A上）
  - 对于 `inbound`：`host_3 == host_2`（在主机B上），且 `source.ip` 对应主机A
- 方案2：基于 IP 地址关联，而不依赖 `host.name`（需要 IP 到主机的映射）
- 方案3：创建两个 Query2（一个匹配 outbound，一个匹配 inbound），分别关联 Query1 和 Query3

### Query3 查询条件

**作用**：检测主机 B 上的提权或远程执行行为（Privilege Escalation / Remote Execution）

#### 必须满足的条件（AND）：
- `_exists_:host.name` - 必须存在主机名称字段

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
  process.parent.name:chrome OR 
  process.parent.name:firefox OR 
  process.parent.name:chromium OR 
  process.parent.name:thunderbird OR 
  process.parent.name:evolution OR 
  process.parent.name:geary
)) OR (event.category:authentication AND event.action:user_login) AND _exists_:host.name"""
```

---

## 父进程特征说明

### 可疑父进程列表

| 父进程名 | 类型 | 说明 |
|---------|------|------|
| `chrome` | 浏览器 | Chrome 浏览器（Linux） |
| `firefox` | 浏览器 | Firefox 浏览器（Linux） |
| `chromium` | 浏览器 | Chromium 浏览器（Linux） |
| `thunderbird` | 邮件客户端 | Thunderbird 邮件客户端（Linux） |
| `evolution` | 邮件客户端 | Evolution 邮件客户端（Linux） |
| `geary` | 邮件客户端 | Geary 邮件客户端（Linux） |

**注意**：已移除 Windows 进程名（`.exe` 后缀），因为系统现在只支持 Linux/Unix 环境。

### 为什么这些父进程被认为是可疑的？

#### 1. 攻击向量（Attack Vector）
- **浏览器启动提权工具**：通常表示通过网页/恶意链接触发的攻击
  - 用户点击恶意链接 → 浏览器下载并执行 → 提权工具启动
  - 这是常见的初始访问和提权攻击链
  
- **邮件客户端启动提权工具**：通常表示通过邮件附件/链接触发的攻击
  - 用户打开恶意邮件附件 → 邮件客户端执行 → 提权工具启动
  - 这是钓鱼攻击的常见模式

#### 2. 异常行为模式（Linux/Unix）
- **正常情况**：提权工具通常由以下进程启动：
  - `bash` / `sh` - Shell 执行
  - `systemd` - 系统服务启动
  - `cron` - 定时任务执行
  - `sshd` - SSH 会话执行
  
- **异常情况**：从浏览器/邮件客户端启动提权工具
  - 浏览器不应该直接启动提权工具
  - 这通常表示通过网页/恶意链接触发的攻击
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

#### 关联策略：最近匹配（Nearest Match）

为了避免笛卡尔积问题，采用**以 Query2 为中心的最近匹配策略**：
- 对于每个 Query2 事件，找到时间最近的 Query1 事件（在同一主机上，时间 <= e2）
- 对于每个 Query2 事件，找到时间最近的 Query3 事件（在不同主机上，时间 >= e2）
- 每个 Query2 事件最多产生一个关联，避免重复和误报

#### Query1 ↔ Query2（主机A上的提权事件 ↔ 从A到B的网络连接）
- **条件1**：Query1 的事件在主机A上，Query2 的源主机也是主机A（`host_1 == host_2`）
  - 要求：Query1 和 Query2 都必须有 `host.name` 字段，且值相同
- **条件2**：用户相同（增强关联性）
- **条件3**：时间顺序：Query1 的时间 <= Query2 的时间（`timestamp_1 <= timestamp_2`）
- **条件4**：最近匹配：在所有满足条件的 Query1 事件中，选择时间最接近 Query2 的事件
- **说明**：Query1 的提权事件没有网络IP信息，因此基于主机名称和用户名称关联

#### Query2 ↔ Query3（从A到B的网络连接 ↔ 主机B上的提权事件）
- **条件1**：Query2 的 `destination.ip` 对应主机B
- **条件2**：Query3 的事件在主机B上（`host_3`）
- **条件3**：Query2 的源主机与 Query3 的主机不同（`host_2 != host_3`）
  - 要求：Query2 和 Query3 都必须有 `host.name` 字段，且值不同
- **条件4**：IP地址匹配验证（**新增**）：
  - 如果 Query3 的事件包含 `host.ip` 字段，则验证 Query2 的 `destination.ip` 是否在 `host.ip` 列表中
  - 如果 Query3 的事件没有 `host.ip` 字段，则放宽条件（基于主机名称匹配）
  - **目的**：确保 Query2 连接的目标IP确实对应 Query3 所在的主机
- **条件5**：用户相同（增强关联性）
- **条件6**：时间顺序：Query2 的时间 <= Query3 的时间（`timestamp_2 <= timestamp_3`）
- **条件7**：最近匹配：在所有满足条件的 Query3 事件中，选择时间最接近 Query2 的事件
- **说明**：Query3 的提权事件通常没有网络IP信息，但如果包含 `host.ip` 字段，可以用来验证 Query2 的 `destination.ip` 是否匹配。Query2 必须有 `host.name` 字段才能与 Query1 和 Query3 进行主机比较。

### 关联逻辑特点

1. **IP地址匹配验证（增强）**：
   - Query1 ↔ Query2：基于主机名称匹配（`host_1 == host_2`），不依赖IP
   - Query2 ↔ Query3：**优先使用IP地址验证**（如果 Query3 的事件包含 `host.ip` 字段）
     - 如果 `host.ip` 存在：验证 Query2 的 `destination.ip` 是否在 `host.ip` 列表中
     - 如果 `host.ip` 不存在：放宽条件，仅基于主机名称匹配（`host_2 != host_3`）
   - **优势**：提高关联准确性，避免误关联到错误的主机

2. **时间窗口**：
   - 所有事件必须在 correlation rule 配置的时间窗口内（默认30分钟）

3. **时间顺序检查**：
   - 确保攻击链的时间顺序：Query1 <= Query2 <= Query3
   - 这是横向移动攻击链的典型时间顺序

4. **用户一致性**：
   - 三个事件的用户应该相同（如果存在用户信息）
   - 如果用户信息缺失，也允许关联（基于主机）

5. **避免笛卡尔积**：
   - 使用"最近匹配"策略，每个 Query2 事件最多产生一个关联
   - 大幅减少误报和重复关联
   - 关联数量理论上等于 Query2 事件数量（或更少）

## 实现位置

### 代码文件
- `backend/app/services/opensearch/analysis.py`
  - `create_lateral_movement_correlation_rule()` - 创建横向移动检测的 Correlation Rule（Query1、Query2、Query3 的查询条件）
  - `classify_privilege_escalation_level()` - 分级判断逻辑（Level 1/2/3）
  - `apply_correlation_rule_manually()` - 手动应用规则，在 events 索引中查询并关联
    - **优化**：使用"最近匹配"策略，避免笛卡尔积问题
    - **优化**：添加时间顺序检查（Query1 <= Query2 <= Query3）
    - **优化**：添加去重逻辑和调试信息
  - `aggregate_correlation_chains()` - 聚合关联链

### 测试数据生成
- `backend/app/services/opensearch/scripts/create_correlation_test_data.py` - 生成横向移动攻击链的测试 events 数据

### 相关文档
- `backend/app/services/opensearch/scripts/explain_parent_process_features.py` - 父进程特征说明脚本
- `backend/app/services/opensearch/scripts/explain_privilege_levels.py` - 分级判断说明脚本

---

## 关联逻辑优化效果

### 优化前（笛卡尔积问题）
- **问题**：使用三层嵌套循环，为所有满足条件的组合创建关联
- **结果**：如果有 12 个 Query1 事件、4 个 Query2 事件、12 个 Query3 事件
  - 理论最大关联数：12 × 4 × 12 = 576 个
  - 实际关联数：80 个（受时间窗口和条件限制）
- **问题**：大量重复和误报，难以识别真正的攻击链

### 优化后（最近匹配策略）
- **策略**：以 Query2 为中心，为每个 Query2 事件找到时间最近的 Query1 和 Query3
- **结果**：同样的数据
  - 理论最大关联数：576 个（不变）
  - 实际关联数：4 个（等于 Query2 事件数量）✅
- **优势**：
  - 避免笛卡尔积问题
  - 每个 Query2 事件最多产生一个关联
  - 关联数量可控，易于分析和处理
  - 减少误报和重复

### 优化效果对比

| 指标 | 优化前 | 优化后 | 改善 |
|------|--------|--------|------|
| 关联数量 | 80 个 | 4 个 | ↓ 95% |
| 唯一主机组合 | 2 个 | 2 个 | 保持 |
| 误报率 | 高 | 低 | ↓ 显著 |
| 可分析性 | 差 | 好 | ↑ 显著 |

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

4. **IP地址匹配增强**：
   - 当前基于主机名称匹配，后续可以添加 IP 地址到主机的映射
   - 使用 Query2 的 `destination.ip` 更精确地匹配 Query3 的主机

5. **时间窗口优化**：
   - 当前使用固定时间窗口（30分钟）
   - 可以根据攻击链的特征动态调整时间窗口

---

## 更新日志

### 2024-12-XX
- ✅ 应用方案2：基于父进程特征
- ✅ 更新 Query1 和 Query3 的查询条件
- ✅ 创建方案追踪文档
- ✅ 修复关联逻辑：从基于IP匹配改为基于主机名称和用户名称匹配
- ✅ 强制使用手动应用规则模式（在 events 索引中查询，而不是依赖 OpenSearch API）
- ✅ 创建测试数据生成脚本（生成 events 数据而非 findings 数据）

### 2026-01-15
- ✅ 优化关联逻辑：从笛卡尔积改为"最近匹配"策略
- ✅ 添加时间顺序检查：确保 Query1 <= Query2 <= Query3
- ✅ 添加去重逻辑：避免重复关联
- ✅ 添加调试信息：显示理论最大关联数和实际关联数
- ✅ 优化效果：关联数量从 80 个优化到 4 个（等于 Query2 事件数量）
- ✅ 更新查询条件：所有查询都要求 `_exists_:host.name` 字段
- ✅ **新增**：IP地址匹配验证 - Query2 的 `destination.ip` 与 Query3 的 `host.ip` 匹配验证
- ✅ **新增**：Query2 排除 HTTP/HTTPS 连接（端口80、443、8080、8443）
- ✅ 更新测试数据生成：Query3 事件包含 `host.ip` 字段，用于IP验证
