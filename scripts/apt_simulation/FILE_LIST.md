# APT 模拟工具包 - 文件清单

## 📦 工具包内容

创建时间：2025-01-16
版本：v1.0
用途：使用 Atomic Red Team 在 4 个虚拟机上执行 APT 攻击模拟

---

## 📁 完整文件列表

```
APT_Simulation_Kit/
│
├── 📄 README.md                              # ⭐⭐⭐ 从这里开始！
│   内容：项目介绍、快速开始、文件结构说明
│   适合：所有人，第一次必读
│   阅读时间：5-10 分钟
│
├── 📄 USAGE_GUIDE.md                         # ⭐⭐ 使用指南
│   内容：文件说明、阅读路径、使用场景
│   适合：需要了解文件结构的人
│   阅读时间：5-10 分钟
│
├── 📄 quick_start.md                         # ⭐⭐⭐ 快速上手
│   内容：5 步快速开始、每步详细命令
│   适合：新手、急需快速使用
│   阅读时间：10-15 分钟
│
├── 📄 detailed_guide.md                      # ⭐ 详细教程
│   内容：完整技术原理、系统架构、检测机制
│   适合：想深入理解的人
│   阅读时间：30-40 分钟
│
├── 📁 scripts/                               # 可执行脚本目录
│   │
│   ├── 📜 apt_atomic_manual.sh              # ⭐⭐⭐ 主脚本
│   │   功能：在 4 个虚拟机上执行完整 APT 攻击
│   │   使用：./apt_atomic_manual.sh
│   │   时间：10-15 分钟（执行时间）
│   │   需要：SSH 免密登录
│   │
│   ├── 📜 setup_ssh.sh                       # ⭐⭐ SSH 配置
│   │   功能：配置 SSH 免密登录
│   │   使用：./setup_ssh.sh
│   │   时间：2-3 分钟
│   │   需要：虚拟机 IP 地址和密码
│   │
│   └── 📜 verify_detection.sh                # ⭐⭐ 验证脚本
│       功能：验证攻击是否被检测到
│       使用：./verify_detection.sh
│       时间：1 分钟
│       需要：jq 命令
│
├── 📁 attack_scenarios/                      # 攻击剧本说明
│   │
│   ├── 📄 scenario_overview.md               # ⭐⭐⭐ 攻击场景总览
│   │   内容：完整攻击故事、12 个阶段详解
│   │   适合：需要理解攻击剧本的人
│   │   阅读时间：15-20 分钟
│   │
│   └── 📄 stage_by_stage.md                  # ⭐ 分阶段说明
│       内容：每个阶段的详细技术说明
│       适合：需要深入了解每个阶段的人
│       阅读时间：20-30 分钟
│
├── 📁 troubleshooting/                       # 问题排查
│   │
│   └── 📄 common_issues.md                   # ⭐⭐ 常见问题解答
│       内容：SSH、执行、检测等问题
│       适合：遇到问题时查阅
│       阅读时间：按需查阅
│
└── 📁 diagrams/                              # 架构图目录
    （文本描述，方便理解）
```

---

## 🎯 使用建议

### 场景 1：第一次使用

**目标**：快速完成第一次攻击模拟

**步骤**：
1. 阅读 `README.md`（5 分钟）
2. 阅读 `quick_start.md`（10 分钟）
3. 运行 `setup_ssh.sh`（3 分钟）
4. 运行 `apt_atomic_manual.sh`（15 分钟）
5. 运行 `verify_detection.sh`（1 分钟）

**总时间**：约 35 分钟

---

### 场景 2：准备答辩演示

**目标**：全面理解，准备讲解

**步骤**：
1. 阅读 `README.md`
2. 阅读 `scenario_overview.md`
3. 练习执行 `apt_atomic_manual.sh`（至少 3 次）
4. 阅读 `detailed_guide.md`（理解原理）
5. 阅读 `common_issues.md`（准备应对问题）

**总时间**：约 3-4 小时（包括练习）

---

### 场景 3：深入理解原理

**目标**：掌握技术细节

**步骤**：
1. 阅读所有文档
2. 分析脚本源码
3. 查看 Atlas Trace Analyzer 项目源码
4. 研究 Atomic Red Team 和 MITRE ATT&CK

**总时间**：约 1-2 天

---

## 📝 文档特点

### 小白友好

- ✅ 大量图表和示例
- ✅ 步骤详细，每个命令都有说明
- ✅ 常见问题解答
- ✅ 多个阅读路径

### 实用导向

- ✅ 可直接执行的脚本
- ✅ 完整的攻击剧本
- ✅ 真实的检测场景
- ✅ 答辩演示建议

### 专业完整

- ✅ 基于 Atomic Red Team 标准测试
- ✅ 映射到 MITRE ATT&CK 框架
- ✅ 覆盖完整的 Kill Chain
- ✅ 多源检测融合

---

## 🔍 快速查找

### "我想..."

| 我想... | 看这里 |
|---------|--------|
| 快速上手 | `quick_start.md` |
| 理解攻击剧本 | `attack_scenarios/scenario_overview.md` |
| 学习技术原理 | `detailed_guide.md` |
| 解决问题 | `troubleshooting/common_issues.md` |
| 了解文件 | `USAGE_GUIDE.md` 或 `README.md` |

---

## ✅ 检查清单

使用前确认：

- [ ] 已阅读 `README.md`
- [ ] 已阅读 `quick_start.md`
- [ ] 中心机服务已启动
  - [ ] backend
  - [ ] frontend
  - [ ] OpenSearch
  - [ ] Neo4j
- [ ] 4 个虚拟机采集栈已运行
- [ ] 网络互通
- [ ] SSH 可用（免密或记住密码）
- [ ] 已修改脚本中的 IP 地址

---

## 🎓 学习路径

### 路径 1：快速实践（推荐）

```
README.md → quick_start.md → setup_ssh.sh → apt_atomic_manual.sh
```

**时间**：1 小时  
**目标**：完成第一次攻击模拟

---

### 路径 2：全面理解

```
README.md → USAGE_GUIDE.md → scenario_overview.md → 
detailed_guide.md → apt_atomic_manual.sh
```

**时间**：4-6 小时  
**目标**：全面掌握原理和使用

---

### 路径 3：深度学习

```
所有文档 → 脚本源码分析 → Atlas Trace Analyzer 源码 → 
Atomic Red Team 文档 → MITRE ATT&CK 框架
```

**时间**：2-3 天  
**目标**：成为专家

---

## 📞 帮助和支持

### 如果文档不清楚

请告诉我哪一部分不清楚，我会改进

### 如果脚本有问题

请保存错误日志，我可以帮你调试

### 如果功能不够用

我可以添加新的攻击场景或功能

---

## 📊 文件统计

| 类别 | 数量 |
|------|------|
| Markdown 文档 | 8 个 |
| Shell 脚本 | 3 个 |
| 总行数 | 约 3000+ 行 |
| 总字数 | 约 20000+ 字 |

---

## 🎉 开始使用

```bash
cd ~/Desktop/APT_Simulation_Kit

# 第一步：阅读总览
cat README.md

# 第二步：快速开始
cat quick_start.md

# 第三步：执行脚本
cd scripts
./setup_ssh.sh        # 配置 SSH
./apt_atomic_manual.sh # 执行攻击

# 第四步：验证结果
./verify_detection.sh

# 第五步：查看前端
# 打开 http://localhost:3000
```

---

**祝使用愉快！** 🚀

---

**最后更新**：2025-01-16  
**版本**：v1.0  
**作者**：Attack Trace Analyzer 项目组
