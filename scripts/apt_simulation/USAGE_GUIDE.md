# 使用指南总览

## 📁 文件清单

```
APT_Simulation_Kit/
├── README.md                           # ⭐ 总览文档（从这里开始）
├── quick_start.md                      # ⭐ 快速开始（5分钟上手）
├── USAGE_GUIDE.md                      # 📖 这个文件（文件说明）
├── detailed_guide.md                   # 📖 详细教程（完整步骤）
│
├── scripts/                            # 📜 可执行脚本目录
│   ├── apt_atomic_manual.sh           # ⭐⭐⭐ 主脚本（推荐使用）
│   ├── apt_atomic_orchestrator.sh     # 自动化版本（需要配置）
│   ├── setup_ssh.sh                   # SSH 一键配置
│   └── verify_detection.sh            # 验证检测结果
│
├── attack_scenarios/                   # 🎭 攻击剧本说明
│   ├── scenario_overview.md           # ⭐ 攻击场景总览
│   └── stage_by_stage.md              # 12个阶段详解
│
├── troubleshooting/                    # 🔧 问题排查
│   └── common_issues.md               # 常见问题解答
│
└── diagrams/                           # 📊 架构图（文本描述）
```

---

## 🎯 不同角色的阅读路径

### 角色 1：完全新手（第一次使用）

**目标**：快速完成第一次攻击模拟

**阅读顺序**：
1. `README.md` - 了解这是什么
2. `quick_start.md` - 快速上手
3. `scripts/setup_ssh.sh` - 配置 SSH
4. `scripts/apt_atomic_manual.sh` - 执行攻击
5. `scripts/verify_detection.sh` - 验证结果

**时间**：30 分钟

---

### 角色 2：需要演示给老师看

**目标**：准备答辩演示

**阅读顺序**：
1. `README.md` - 理解整体架构
2. `attack_scenarios/scenario_overview.md` - 理解攻击剧本
3. `quick_start.md` - 练习执行
4. `detailed_guide.md` - 深入理解原理
5. `troubleshooting/common_issues.md` - 准备应对问题

**时间**：2-3 小时（包括练习）

---

### 角色 3：想深入理解系统原理

**目标**：掌握技术细节

**阅读顺序**：
1. `README.md` - 架构概览
2. `detailed_guide.md` - 完整技术文档
3. `attack_scenarios/stage_by_stage.md` - 每个阶段详解
4. 查看脚本源码（`scripts/apt_atomic_manual.sh`）

**时间**：4-6 小时

---

## 📝 各文件详细说明

### 必读文件（⭐⭐⭐）

#### 1. README.md

**内容**：
- 项目介绍
- 文件结构
- 快速开始
- 预期结果

**适合**：所有人，第一次必读

**阅读时间**：5-10 分钟

---

#### 2. quick_start.md

**内容**：
- 5 步快速上手
- 每步都有详细命令
- 预期输出示例
- 快速问题解决

**适合**：新手、急需快速使用

**阅读时间**：10-15 分钟

---

#### 3. scripts/apt_atomic_manual.sh

**内容**：
- 完整攻击脚本
- 12 个阶段的实现
- 自动化执行

**适合**：直接执行

**使用时间**：10-15 分钟（执行时间）

---

### 推荐阅读（⭐⭐）

#### 4. attack_scenarios/scenario_overview.md

**内容**：
- 完整的攻击故事
- 12 个阶段详解
- MITRE ATT&CK 映射
- 攻击链图

**适合**：需要理解攻击剧本的人

**阅读时间**：15-20 分钟

---

#### 5. troubleshooting/common_issues.md

**内容**：
- 常见问题解答
- 详细的排查步骤
- 解决方案

**适合**：遇到问题时查看

**阅读时间**：按需查阅

---

### 进阶阅读（⭐）

#### 6. detailed_guide.md

**内容**：
- 完整的技术原理
- 系统架构详解
- 检测机制说明
- 高级用法

**适合**：想深入理解的人

**阅读时间**：30-40 分钟

---

#### 7. scripts/setup_ssh.sh

**内容**：
- SSH 免密配置脚本
- 自动化配置过程

**适合**：需要配置 SSH 的人

**使用时间**：2-3 分钟

---

#### 8. scripts/verify_detection.sh

**内容**：
- 检测结果验证脚本
- 自动化检查各项指标

**适合**：验证攻击是否成功

**使用时间**：1 分钟

---

## 🚀 典型使用场景

### 场景 1：练习使用

```bash
# 第 1 步：阅读文档
cat README.md
cat quick_start.md

# 第 2 步：配置 SSH
cd scripts
./setup_ssh.sh

# 第 3 步：执行攻击
./apt_atomic_manual.sh

# 第 4 步：验证结果
./verify_detection.sh

# 第 5 步：查看前端
# 打开 http://localhost:3000
```

---

### 场景 2：准备答辩演示

```bash
# 第 1 步：理解攻击剧本
cat attack_scenarios/scenario_overview.md

# 第 2 步：练习执行
cd scripts
./apt_atomic_manual.sh

# 第 3 步：准备 PPT
# 重点说明：
# - 4 台虚拟机的角色
# - 12 个攻击阶段
# - 检测系统如何工作

# 第 4 步：准备应对问题
cat ../troubleshooting/common_issues.md

# 第 5 步：现场演示
# - 启动所有服务
# - 执行攻击脚本
# - 展示检测结果
```

---

### 场景 3：调试问题

```bash
# 第 1 步：检查脚本执行
cd scripts
./apt_atomic_manual.sh

# 第 2 步：查看日志
cat apt_manual_*.log | less

# 第 3 步：验证检测
./verify_detection.sh

# 第 4 步：如果有问题
cat ../troubleshooting/common_issues.md | grep -A 10 "你的问题"
```

---

## 📊 文件关系图

```
使用流程
────────
┌─────────────┐
│ 开始使用    │
└──────┬──────┘
       │
       ▼
┌─────────────┐      ┌──────────────────┐
│ README.md   │ ──→  │ 了解项目功能      │
└──────┬──────┘      └──────────────────┘
       │
       ▼
┌─────────────┐      ┌──────────────────┐
│quick_start  │ ──→  │ 快速上手          │
│.md          │      └──────────────────┘
└──────┬──────┘
       │
       ▼
┌─────────────────────────┐      ┌──────────────────┐
│ setup_ssh.sh            │ ──→  │ 配置 SSH          │
└──────┬──────────────────┘      └──────────────────┘
       │
       ▼
┌─────────────────────────┐      ┌──────────────────┐
│ apt_atomic_manual.sh    │ ──→  │ 执行攻击          │
└──────┬──────────────────┘      └──────────────────┘
       │
       ▼
┌─────────────────────────┐      ┌──────────────────┐
│ verify_detection.sh     │ ──→  │ 验证结果          │
└─────────────────────────┘      └──────────────────┘
       │
       ▼
┌─────────────────────────┐      ┌──────────────────┐
│ 前端界面                │ ──→  │ 查看图谱和报告    │
│ http://localhost:3000   │      └──────────────────┘
└─────────────────────────┘

理解流程
────────
┌─────────────────────────┐      ┌──────────────────┐
│ scenario_overview.md    │ ──→  │ 理解攻击剧本      │
└─────────────────────────┘      └──────────────────┘
       │
       ▼
┌─────────────────────────┐      ┌──────────────────┐
│ detailed_guide.md       │ ──→  │ 深入学习原理      │
└─────────────────────────┘      └──────────────────┘

问题解决
────────
┌─────────────────────────┐      ┌──────────────────┐
│ common_issues.md        │ ──→  │ 查找解决方案      │
└─────────────────────────┘      └──────────────────┘
```

---

## ✅ 使用前检查清单

在使用这个工具包前，确保：

- [ ] 已阅读 `README.md`
- [ ] 已阅读 `quick_start.md`
- [ ] 中心机服务已启动
  - [ ] backend
  - [ ] frontend
  - [ ] OpenSearch
  - [ ] Neo4j
- [ ] 4 个虚拟机采集栈已运行
- [ ] 网络互通（可以 ping 通所有虚拟机）
- [ ] SSH 可用（免密或记住密码）
- [ ] 已修改脚本中的 IP 地址配置

---

## 🎯 学习建议

### 第 1 天：熟悉环境

1. 阅读 `README.md` 和 `quick_start.md`
2. 配置 SSH
3. 执行一次攻击剧本
4. 查看检测结果

**时间**：1-2 小时

---

### 第 2 天：理解原理

1. 阅读 `attack_scenarios/scenario_overview.md`
2. 阅读 `detailed_guide.md`
3. 分析脚本源码
4. 在前端查看每个阶段的效果

**时间**：2-3 小时

---

### 第 3 天：准备演示

1. 练习执行攻击剧本
2. 准备 PPT 讲解材料
3. 准备应对问题的答案
4. 录制演示视频作为备份

**时间**：2-3 小时

---

## 📞 需要帮助？

### 问题 1：不知道从哪里开始

**解决**：从 `README.md` 开始，然后是 `quick_start.md`

### 问题 2：执行脚本出错

**解决**：查看 `troubleshooting/common_issues.md`

### 问题 3：不理解攻击剧本

**解决**：阅读 `attack_scenarios/scenario_overview.md`

### 问题 4：想深入了解

**解决**：阅读 `detailed_guide.md` 和脚本源码

---

## 🎓 扩展学习

### 推荐资源

1. **Atomic Red Team 官方文档**
   https://redcanary.com/github/atomic-red-team

2. **MITRE ATT&CK 框架**
   https://attack.mitre.org/

3. **Kill Chain 模型**
   Lockheed Martin Kill Chain

4. **你的项目文档**
   `attack-trace-analyzer/docs/`

---

## 📝 反馈和改进

如果你觉得：

- **文档不清楚**：请告诉我哪一部分，我会改进
- **脚本有问题**：请保存错误日志，我可以调试
- **功能不够用**：我可以添加新的攻击场景

---

**祝你使用愉快！** 🎉

---

## 📋 快速命令参考

```bash
# 配置 SSH
cd ~/Desktop/APT_Simulation_Kit/scripts
./setup_ssh.sh

# 执行攻击
./apt_atomic_manual.sh

# 验证结果
./verify_detection.sh

# 查看日志
cat apt_manual_*.log | less

# 清理虚拟机标记
for i in 1 2 3 4; do ssh ubuntu@192.168.1.1$i "rm -f /tmp/apt_*"; done
```
