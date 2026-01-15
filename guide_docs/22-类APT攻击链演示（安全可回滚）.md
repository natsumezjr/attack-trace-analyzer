# 类 APT 攻击链演示（安全、可回滚）

目标：在不做真实入侵利用的前提下，用**最少动作**制造你们系统需要的证据（网络流量 + 主机日志 + 主机行为），并形成一条“看起来像 APT”的链路，便于讲解与验收。

> 安全边界：不包含漏洞利用、提权、持久化、破坏性操作；只做可控的“下载 → 执行（良性脚本）→ 远程登录（SSH）→ 内网探测（只读）”。

---

## 0. 角色与映射（建议口径）

- **攻击者节点（模拟）**：用你的终端即可（本机或组员机器）
- **受害者节点（模拟）**：`10.92.35.13`（你的一台服务器）
- **C2**：DNS `10.92.35.50`，HTTP `10.92.35.51`，域名 `c2.lab.local`

你们系统的三路证据来源：

- **网络流量（Suricata）**：DNS/HTTP/SSH 的 flow 与应用层字段
- **主机日志（Filebeat）**：SSH 登录/认证日志、系统日志
- **主机行为（Falco）**：进程执行、文件写入、网络连接等规则触发（是否触发取决于规则集）

---

## 1. 攻击链步骤（动作 → 预期证据）

### Step A：C2 解析与连通（对应“C2/Discovery”风格）

动作（在服务器上执行，或任意能访问 C2 的机器上执行）：

```bash
dig @10.92.35.50 c2.lab.local +noall +answer +time=1 +tries=1
curl -s http://10.92.35.51/payload && echo
```

预期证据：

- Suricata：出现 `destination.port:53`、`destination.port:80` 的网络事件；DNS 里能看到 `c2.lab.local`
- 抓包（验收）：宿主机 `macvlan0` 能抓到 53/80 往返

---

### Step B：下载“载荷”（良性文本）到受害机（对应“Command and Control / Ingress Tool Transfer”风格）

动作（在 `10.92.35.13` 上执行）：

```bash
mkdir -p /tmp/apt-demo
curl -s http://10.92.35.51/payload -o /tmp/apt-demo/payload.txt
sha256sum /tmp/apt-demo/payload.txt
```

预期证据：

- Suricata：HTTP 请求 `/payload`
- Falco（可能）：`curl` 写文件到 `/tmp/apt-demo/`、相关进程执行
- Filebeat（可能）：系统日志里出现网络工具执行痕迹（取决于发行版日志配置）

---

### Step C：模拟“执行”（对应“Execution”风格）

说明：不运行二进制，只执行一个**打印信息**的脚本，产生明确的进程行为与文件 I/O。

动作（在 `10.92.35.13` 上执行）：

```bash
cat > /tmp/apt-demo/run.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
date
echo "[demo] benign execution"
echo "[demo] host=$(hostname) user=$(id -un)"
EOF
chmod +x /tmp/apt-demo/run.sh
/tmp/apt-demo/run.sh | tee /tmp/apt-demo/output.log
```

预期证据：

- Falco：`bash` / `run.sh` 进程执行、写入 `output.log`
- Filebeat：可能采到 shell 历史/系统日志（取决于采集配置）

---

### Step D：模拟“横向移动”（对应“Lateral Movement”风格）

说明：在单机条件下，我们用 **SSH 会话**来模拟“从一个节点远程登录到另一个节点”。即使源 IP 是同网段内的真实机器/同机回环，也能产生日志与流量证据。

动作（从另一台内网机器执行最佳；没有就从本机执行 `ssh ubuntu@10.92.35.13`）：

```bash
ssh ubuntu@10.92.35.13 "hostname; whoami; date"
```

预期证据：

- Filebeat：`/var/log/auth.log`（或等价日志）里出现 sshd 登录记录（`user.name`、`source.ip`、成功/失败）
- Suricata：`destination.port:22` 的 TCP flow（若 Suricata 抓的是 `ens5f1`，需要确保 SSH 流量确实经过该接口）
- Falco（可能）：`sshd` 相关进程/会话行为

---

### Step E：模拟“内网发现/收集（只读）”（对应“Discovery / Collection”风格）

动作（通过刚才的 SSH 会话，在受害机执行只读探测）：

```bash
ssh ubuntu@10.92.35.13 "ip -br a; ss -lntup | head; ls -la /tmp/apt-demo | head"
```

预期证据：

- Filebeat：命令执行带来的系统日志变化（不一定有，但 SSH 会话一定有）
- Falco：常见的“枚举/读取系统信息”行为可能触发规则（取决于规则集）

---

## 2. 演示时怎么讲（30 秒口径）

1) 我们先让受害机解析并访问 C2（DNS+HTTP），Suricata 能看到 53/80 流量；  
2) 再从 C2 拉一个“良性载荷”到 `/tmp`，产生下载与写文件行为；  
3) 执行一个无害脚本，产生明确的进程/文件证据（Falco 最容易展示）；  
4) 用 SSH 会话模拟横向移动，Filebeat 能稳定采到认证日志；  
5) 最后做只读发现，形成完整时间线，便于你们后续把事件映射到 ATT&CK 阶段。

---

## 3. 可回滚清理

```bash
rm -rf /tmp/apt-demo
```

