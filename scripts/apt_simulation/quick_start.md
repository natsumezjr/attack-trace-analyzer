# 快速开始指南

## 🎯 5 分钟快速上手

本指南帮你最快速度完成第一次 APT 攻击模拟。

---

## 第 1 步：确认你的环境（1 分钟）

### 你需要什么？

一台宿主机（中心机） + 四台虚拟机

```
┌────────────────────────────────────┐
│  宿主机（你的 MacBook）              │
│  ┌──────────────────────────────┐  │
│  │ 中心机                        │  │
│  │ - backend (FastAPI)          │  │
│  │ - frontend (Next.js)         │  │
│  │ - OpenSearch + Neo4j         │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
          │
          │ 网络连接
          │
    ┌─────┼─────┬─────┬─────┐
    │     │     │     │     │
┌───▼─┐ ┌▼───┐ ┌▼───┐ ┌▼───┐
│ VM1 │ │VM2 │ │VM3 │ │VM4 │
│192.│ │192.│ │192.│ │192.│
│1.11│ │1.12│ │1.13│ │1.14│
└───┘ └────┘ └────┘ └────┘
```

### 检查虚拟机是否运行采集栈

在每台虚拟机上执行：

```bash
docker ps
```

应该看到这些容器在运行：
- falco
- filebeat
- suricata
- rabbitmq
- go-backend

### 检查中心机是否运行

在宿主机上执行：

```bash
# 检查后端
curl http://localhost:8001/health

# 应该返回：{"status":"ok"}

# 检查前端
curl http://localhost:3000

# 应该返回 HTML 内容
```

---

## 第 2 步：配置 SSH（2 分钟）

### 为什么需要 SSH？

因为攻击脚本需要从中心机远程控制 4 个虚拟机执行攻击命令。

### 方法 A：使用自动脚本（推荐）

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
chmod +x setup_ssh.sh
./setup_ssh.sh
```

脚本会提示你输入 4 次密码（每个虚拟机一次）。

### 方法 B：手动配置

如果脚本失败，手动执行：

```bash
# 生成密钥（如果没有）
ssh-keygen -t rsa -b 4096

# 复制到各个虚拟机
ssh-copy-id ubuntu@192.168.1.11
ssh-copy-id ubuntu@192.168.1.12
ssh-copy-id ubuntu@192.168.1.13
ssh-copy-id ubuntu@192.168.1.14
```

### 验证 SSH 配置

```bash
# 应该能直接登录，不需要密码
ssh ubuntu@192.168.1.11 "hostname"
```

---

## 第 3 步：修改配置（1 分钟）

### 编辑脚本，修改虚拟机 IP

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
nano apt_atomic_manual.sh
```

找到这几行，修改成你的虚拟机 IP：

```bash
VICTIM_01="ubuntu@192.168.1.11"  # 改成你的 victim-01 IP
VICTIM_02="ubuntu@192.168.1.12"  # 改成你的 victim-02 IP
VICTIM_03="ubuntu@192.168.1.13"  # 改成你的 victim-03 IP
VICTIM_04="ubuntu@192.168.1.14"  # 改成你的 victim-04 IP
```

### 修改等待时间（可选）

```bash
WAIT_TIME=20  # 每个阶段等待 20 秒
```

如果网络快，可以改成 10-15 秒。

---

## 第 4 步：执行攻击（10-15 分钟）

### 运行脚本

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
chmod +x apt_atomic_manual.sh
./apt_atomic_manual.sh
```

### 你会看到什么？

```
[2025-01-16 14:30:22] =========================================
[2025-01-16 14:30:22] APT 攻击 - 手动执行原子测试
[2025-01-16 14:30:22] =========================================

[2025-01-16 14:30:25] 【victim-01】Initial Access - T1190
[2025-01-16 14:30:25] 在 ubuntu@192.168.1.11 上执行: T1190 - Web Shell Initial Access
APT_T1190_MARKER=1737000625
[2025-01-16 14:30:25] 等待 20 秒让中心机采集数据...

[2025-01-16 14:30:48] 【victim-01】Execution - T1059.004
...

[2025-01-16 14:42:15] =========================================
[2025-01-16 14:42:15] APT 攻击剧本执行完成！
[2025-01-16 14:42:15] =========================================
```

### 执行过程中发生了什么？

```
时间线：
─────────────────────────────────────────────

00:00  victim-01 执行 Web Shell 访问
       ↓ Falco 检测到异常进程
       ↓ Suricata 捕获网络流量
       
00:20  victim-01 执行 Bash 命令
       ↓ Filebeat 记录系统日志
       
00:40  victim-01 创建 systemd 后门
       ↓ Falco 检测到服务创建
       
01:00  victim-01 读取 /etc/shadow
       ↓ Filebeat 记录认证日志
       
01:20  victim-01 SSH 连接到 victim-02
       ↓ Suricata 捕获横向移动
       
01:40  victim-02 执行文件扫描
       ↓ Falco 检测到文件访问
       
...    （持续 12 个阶段）
       
15:00  所有阶段完成
       ↓ 中心机完成分析
       ↓ 等待你在前端查看
```

---

## 第 5 步：查看结果（5 分钟）

### 1. 打开前端界面

```bash
# 在浏览器中打开
http://localhost:3000
```

### 2. 查看事件是否入库

在前端界面：
- 点击"事件搜索"
- 点击"搜索"按钮
- 应该看到很多事件（几百到几千条）

或者在终端：

```bash
curl -X POST http://localhost:8001/api/v1/events/search \
  -H "Content-Type: application/json" \
  -d '{"size": 1}' | jq '.total'
```

应该返回一个数字 > 0

### 3. 查看图谱可视化

在前端界面：
- 点击"图谱"标签
- 应该看到节点和连线

**期望看到的图谱**：

```
      [Attacker]
          ↓
    [victim-01]
          ↓
    [victim-02]
          ↓
    [victim-03]
          ↓
    [victim-04]
```

### 4. 创建溯源任务

在前端界面：
- 点击"溯源任务"
- 点击"新建任务"
- 选择起始节点（任意节点）
- 选择分析类型：KillChain
- 点击"提交"

等待 10-30 秒，任务完成后点击查看结果。

### 5. 查看攻击报告

报告应该显示：

```
Kill Chain Analysis Report
===========================

Attack Stages Detected:
1. Initial Access: T1190 (victim-01)
2. Execution: T1059.004 (victim-01)
3. Persistence: T1053.003 (victim-01)
4. Credential Access: T1003.003 (victim-01)
5. Lateral Movement: T1021.004 (victim-01 → victim-02)
6. Discovery: T1083 (victim-02)
7. Collection: T1005 (victim-02)
8. Lateral Movement: T1077.004 (victim-02 → victim-03)
9. Privilege Escalation: T1068.001 (victim-03)
10. Lateral Movement: T1558.003 (victim-03 → victim-04)
11. Command & Control: T1071.001 (victim-04)
12. Impact: T1485 (victim-04)

Confidence Score: 0.87
Related APT Groups: APT29, APT41
```

---

## ❓ 快速问题解决

### 问题 1：SSH 连接失败

```bash
# 测试连接
ssh ubuntu@192.168.1.11

# 如果失败，检查：
1. 虚拟机是否开机？
2. IP 地址是否正确？
3. SSH 服务是否运行？（在虚拟机上：sudo systemctl status ssh）
```

### 问题 2：脚本执行但前端看不到数据

```bash
# 检查虚拟机采集栈
ssh ubuntu@192.168.1.11 "docker ps"

# 应该看到 falco, filebeat, suricata 等容器

# 检查虚拟机 API
curl http://192.168.1.11:18881/falco

# 应该返回 JSON 数据
```

### 问题 3：执行太慢

```bash
# 编辑脚本，减少等待时间
nano ~/Desktop/APT_Simulation_Kit/scripts/apt_atomic_manual.sh

# 修改 WAIT_TIME=20 改成 WAIT_TIME=10
```

---

## ✅ 成功标志

如果你看到了以下内容，说明成功了：

1. ✅ 脚本执行完显示"所有攻击阶段完成"
2. ✅ 前端事件搜索返回 > 0 条记录
3. ✅ 图谱界面显示节点和连线
4. ✅ KillChain 报告显示 12 个阶段

---

## 🎯 下一步

- 阅读 `attack_scenarios/scenario_overview.md` 了解攻击剧本详情
- 阅读 `detailed_guide.md` 了解系统原理
- 准备答辩 PPT 和演示流程

**恭喜！你完成了第一次 APT 攻击模拟！** 🎉
