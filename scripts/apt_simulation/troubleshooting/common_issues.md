# 常见问题解答

## ❓ 我不知道从哪里开始

**解决**：按这个顺序来

1. 先读 `../README.md`（了解整体）
2. 再读 `../quick_start.md`（快速上手）
3. 执行脚本前先读 `../attack_scenarios/scenario_overview.md`（理解剧本）

---

## ❓ 我不知道我的虚拟机 IP 地址

### 方法 1：在虚拟机上查看

```bash
# 在虚拟机终端执行
ip addr show | grep "inet " | grep -v 127.0.0.1
```

输出示例：
```
inet 192.168.1.11/24 brd 192.168.1.255 scope global eth0
```
IP 就是 `192.168.1.11`

### 方法 2：在中心机上扫描

```bash
# 扫描局域网（需要安装 nmap）
nmap -sn 192.168.1.0/24
```

会列出所有在线的机器及其 IP

---

## ❓ SSH 连接失败

### 症状

```
ssh: connect to host 192.168.1.11 port 22: Connection refused
```

### 排查步骤

#### 1. 检查虚拟机是否开机

```bash
ping 192.168.1.11
```

如果不通，说明虚拟机没开机或网络配置有问题。

#### 2. 检查 SSH 服务是否运行

```bash
# 在虚拟机上执行
sudo systemctl status ssh
```

应该显示：
```
● ssh.service - OpenBSD Secure Shell server
   Loaded: loaded
   Active: active (running)
```

如果不是 `active (running)`，启动服务：

```bash
sudo systemctl start ssh
sudo systemctl enable ssh
```

#### 3. 检查防火墙

```bash
# 在虚拟机上检查防火墙状态
sudo ufw status
```

如果启用了防火墙，允许 SSH：

```bash
sudo ufw allow ssh
```

#### 4. 检查用户名

确认虚拟机的用户名是 `ubuntu` 还是其他：

```bash
# 在虚拟机上
whoami
```

---

## ❓ 脚本执行到一半卡住了

### 可能原因 1：某个虚拟机没响应

**解决**：按 `Ctrl+C` 终止脚本，检查虚拟机状态

```bash
ssh ubuntu@192.168.1.11 "docker ps"
ssh ubuntu@192.168.1.12 "docker ps"
ssh ubuntu@192.168.1.13 "docker ps"
ssh ubuntu@192.168.1.14 "docker ps"
```

确保所有虚拟机的采集栈都在运行。

### 可能原因 2：网络延迟太高

**解决**：编辑脚本，增加超时时间

```bash
nano ~/Desktop/APT_Simulation_Kit/scripts/apt_atomic_manual.sh

# 找到这一行
WAIT_TIME=20

# 改成
WAIT_TIME=30
```

### 可能原因 3：虚拟机资源不足

**解决**：检查虚拟机内存和 CPU

```bash
# 在虚拟机上
free -h
top
```

如果内存不足，考虑增加虚拟机内存分配。

---

## ❓ 脚本执行完了但前端看不到数据

### 检查清单

#### 1. 检查虚拟机采集栈

```bash
# SSH 到虚拟机
ssh ubuntu@192.168.1.11

# 检查容器
docker ps
```

应该看到这些容器：
- falco
- filebeat
- suricata
- rabbitmq
- go-backend

**如果容器没运行**：

```bash
cd ~/client  # 或者你的 client 目录
docker compose up -d
```

#### 2. 检查虚拟机 API

```bash
# 在中心机上
curl http://192.168.1.11:18881/falco
```

应该返回 JSON 数据，比如：
```json
{"total": 123, "events": [...]}
```

**如果连接失败**：
- 检查虚拟机防火墙
- 检查端口是否正确（`18881` 或其他）
- 检查 go-backend 容器是否运行

#### 3. 检查中心机轮询

```bash
curl http://localhost:8001/api/v1/clients
```

应该看到所有虚拟机已注册：

```json
{
  "status": "ok",
  "clients": [
    {"client_id": "client-01", "poll": {"status": "ok"}},
    {"client_id": "client-02", "poll": {"status": "ok"}},
    ...
  ]
}
```

**如果 `poll.status` 是 `error`**：
- 检查虚拟机 IP 是否正确
- 检查网络连通性

#### 4. 检查 OpenSearch

```bash
curl -k -u admin:OpenSearch@2024!Dev https://localhost:9200/_cat/indices
```

应该看到 `telemetry-*` 索引：

```
green open telemetry-2025-01-16 ...
```

**如果没有索引**：
- 检查后端日志
- 重启后端服务

#### 5. 检查后端日志

```bash
# 查看后端输出
# 后端应该显示轮询日志
```

---

## ❓ 前端图谱没有节点

### 可能原因 1：图谱还没构建完成

**解决**：等待 1-2 分钟，后端会定期构建图谱

### 可能原因 2：事件数据不符合要求

**解决**：检查事件是否有必要的字段

```bash
curl -X POST http://localhost:8001/api/v1/events/search \
  -H "Content-Type: application/json" \
  -d '{"size": 1}' | jq '.events[0]'
```

确保有这些字段：
- `host.id`
- `host.name`
- 至少一个实体字段（`process`, `file`, `ip`, `domain` 等）

### 可能原因 3：图谱构建出错

**解决**：检查后端日志，查找错误信息

---

## ❓ KillChain 分析没有结果

### 可能原因 1：事件太少

**解决**：确保攻击脚本完整执行

重新运行攻击脚本：

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
./apt_atomic_manual.sh
```

### 可能原因 2：LLM 服务不可用

**解决**：使用 mock 模式

```bash
export LLM_PROVIDER=mock
# 然后重启后端
```

### 可能原因 3：图谱节点不连通

**解决**：检查 Neo4j 图谱

```bash
# 浏览器打开
http://localhost:7474

# 执行 Cypher 查询
MATCH (n) RETURN count(n)
```

应该有 > 0 个节点。

---

## ❓ "Permission denied" 错误

### 症状

```
bash: ./apt_atomic_manual.sh: Permission denied
```

**解决**：添加执行权限

```bash
chmod +x ~/Desktop/APT_Simulation_Kit/scripts/apt_atomic_manual.sh
```

---

## ❓ "command not found: jq"

### 症状

验证脚本执行时报错：`jq: command not found`

**解决**：安装 jq

```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq
```

或者修改验证脚本，去掉 `jq` 依赖：

```bash
nano scripts/verify_detection.sh

# 将 | jq '.total' 改为 | grep '"total"'
```

---

## ❓ 我不知道攻击脚本执行到哪一步了

### 查看日志

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
ls -la apt_manual_*.log
```

查看最新的日志文件：

```bash
cat apt_manual_20250116_143022.log | less
```

或者实时查看：

```bash
tail -f apt_manual_*.log
```

### 查看标记文件

在虚拟机上检查标记文件：

```bash
ssh ubuntu@192.168.1.11 "ls -la /tmp/apt_*_marker.txt /tmp/apt_stage*.txt"
```

---

## ❓ 我想重新执行攻击

### 清理旧数据

#### 方法 1：重启 OpenSearch

```bash
cd ~/Desktop/APT_Simulation_Kit
# 确认要删除所有数据

# 删除索引
curl -k -u admin:OpenSearch@2024!Dev \
  -X DELETE https://localhost:9200/telemetry-*
```

#### 方法 2：重启 Neo4j

```bash
cd ~/path/to/attack-trace-analyzer/backend
docker compose restart neo4j
```

#### 方法 3：清理虚拟机标记

```bash
for i in 1 2 3 4; do
  ssh ubuntu@192.168.1.1$i "rm -f /tmp/apt_*"
done
```

### 重新执行

```bash
cd ~/Desktop/APT_Simulation_Kit/scripts
./apt_atomic_manual.sh
```

---

## ❓ 演示时可能遇到的问题

### 问题 1：投影仪/屏幕分辨率

**准备**：提前测试

```bash
# 调整前端界面大小
# 在浏览器中按 F12（开发者工具）
# 调整窗口大小
```

### 问题 2：网络突然不通

**预案**：准备离线截图和录像

```bash
# 提前录制一次成功的演示
# 如果现场网络有问题，播放录像
```

### 问题 3：虚拟机崩溃

**预案**：准备虚拟机快照

```bash
# 在演示前创建快照
# 如果出问题，快速恢复
```

---

## ❓ 我想修改攻击剧本

### 添加新的攻击阶段

编辑脚本：

```bash
nano ~/Desktop/APT_Simulation_Kit/scripts/apt_atomic_manual.sh
```

在相应位置添加新的 `remote_exec` 调用：

```bash
log "【Phase X】新的攻击阶段"
log "技术: TXXXX - 技术名称"

remote_exec "$VICTIM_XX" "
    # 你的攻击命令
    logger -t 'APT_ATOMIC' 'TXXXX: 攻击描述'
    echo 'APT_TXXXX_MARKER=\$(date +%s)' > /tmp/apt_stageX.txt
" "TXXXX - 技术名称"
```

### 修改等待时间

```bash
# 找到这一行
WAIT_TIME=20

# 改成你想要的时间（秒）
WAIT_TIME=15
```

### 添加新的虚拟机

1. 修改配置：

```bash
VICTIM_05="ubuntu@192.168.1.15"
```

2. 在脚本中添加对 victim-05 的攻击命令

3. 确保虚拟机运行采集栈

---

## 📞 还没解决问题？

### 收集诊断信息

```bash
cd ~/Desktop/APT_Simulation_Kit

# 运行诊断脚本
bash scripts/verify_detection.sh > diagnostic_output.txt 2>&1

# 收集日志
tar -czf diagnostic_bundle.tar.gz \
  apt_manual_*.log \
  diagnostic_output.txt
```

### 检查清单

- [ ] 所有虚拟机都开机
- [ ] 所有采集栈都运行（`docker ps`）
- [ ] 网络互通（`ping` 测试）
- [ ] SSH 可用（能免密登录）
- [ ] 中心机服务运行（backend + frontend + OpenSearch + Neo4j）
- [ ] 脚本有执行权限（`chmod +x`）
- [ ] 配置正确（IP 地址、用户名）

---

**祝你好运！** 🍀
