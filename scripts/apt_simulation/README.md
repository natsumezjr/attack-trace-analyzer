# APT 模拟工具包 - 完整指南

## 📖 这个工具包是干什么的？

这是一个**教学演示工具包**，用于：
- 在 4 个虚拟机上模拟一次完整的 APT 攻击
- 验证你的 Attack Trace Analyzer 检测系统能否检测到
- 给老师/同学演示项目效果

### ⚠️ 重要说明

```
这是用于安全测试和教学演示的工具
只能在你自己搭建的实验环境中使用
严禁用于非法用途
```

---

## 🎯 使用场景

**场景**：你需要给老师演示你的攻击检测系统

**问题**：不知道怎么在 4 个虚拟机上执行攻击，让系统检测到

**解决**：这个工具包提供了现成的脚本和详细文档

---

## 📁 文件夹结构

```
APT_Simulation_Kit/
├── README.md                    ← 你现在看的这个（总览）
├── quick_start.md               ← 快速开始（5分钟上手）
├── detailed_guide.md            ← 详细教程（完整步骤）
├── scripts/                     ← 所有可执行脚本
│   ├── apt_atomic_manual.sh    ← 手动执行版本（推荐新手）
│   ├── apt_atomic_orchestrator.sh ← 自动化版本（需要配置）
│   ├── setup_ssh.sh             ← SSH 一键配置
│   └── verify_detection.sh      ← 验证检测结果
├── attack_scenarios/            ← 攻击剧本说明
│   ├── scenario_overview.md     ← 攻击链路总览
│   └── stage_by_stage.md        ← 12 个阶段详解
├── troubleshooting/             ← 问题排查
│   └── common_issues.md         ← 常见问题解答
└── diagrams/                    ← 架构图和流程图
```

---

## 🚀 快速开始（3 步）

### 第 1 步：准备环境

你需要：
- ✅ 1 台中心机（运行你的 ATA 项目）
- ✅ 4 台虚拟机（victim-01 到 victim-04，都运行 client 采集栈）
- ✅ 所有机器网络互通

**怎么检查？**

```bash
# 在中心机上 ping 各个虚拟机
ping 192.168.1.11  # victim-01
ping 192.168.1.12  # victim-02
ping 192.168.1.13  # victim-03
ping 192.168.1.14  # victim-04
```

### 第 2 步：配置 SSH（只做一次）

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
chmod +x setup_ssh.sh
./setup_ssh.sh
```

这个脚本会帮你配置 SSH 免密登录，让中心机能自动控制虚拟机。

### 第 3 步：执行攻击剧本

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
chmod +x apt_atomic_manual.sh
./apt_atomic_manual.sh
```

等待约 10-15 分钟，脚本会自动在 4 个虚拟机上执行完整的攻击链。

### 第 4 步：查看检测结果

```bash
# 打开浏览器访问
http://localhost:3000
```

在前端界面：
1. 点击"图谱"查看攻击链可视化
2. 点击"溯源任务"创建 KillChain 分析
3. 查看生成的攻击报告

---

## 📚 文档阅读顺序

如果你是**第一次使用**，按这个顺序读：

```
1. README.md (现在这个)          ← 了解这是什么
2. quick_start.md               ← 快速上手指南
3. attack_scenarios/scenario_overview.md  ← 了解攻击剧本
4. detailed_guide.md            ← 完整详细教程
5. troubleshooting/common_issues.md     ← 遇到问题看这里
```

---

## ✅ 检查清单

演示前确认：

- [ ] 中心机服务已启动（backend + frontend + OpenSearch + Neo4j）
- [ ] 4 个虚拟机采集栈已运行
- [ ] 网络连通（能 ping 通所有虚拟机）
- [ ] SSH 免密已配置（或记住密码）
- [ ] 脚本有执行权限（`chmod +x *.sh`）
- [ ] 已阅读 quick_start.md
- [ ] 已理解攻击剧本（`attack_scenarios/scenario_overview.md`）

---

**祝你演示成功！** 🎉
