# 4个模拟客户机 - APT 攻击测试

本目录包含 4 个模拟客户机，用于测试中心机的完整链路：数据采集 → 入库 → 分析 → KillChain。

---

## 快速开始

### 1. 启动中心机后端

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8001
```

### 2. 启动数据库服务

```bash
cd backend
docker compose up -d
```

### 3. 启动 4 个模拟客户机

```bash
cd tests/e2e/mock_cli
./start_clients.sh
```

### 4. 等待数据轮询

- 中心机每 5 秒自动轮询所有客户机
- 数据会自动入库、分析、生成图谱
- 查看 `client*.log` 确认轮询状态

### 5. 使用前端检测

打开前端界面：
- **查询事件**：验证 APT 攻击事件已入库
- **图谱可视化**：查看攻击路径
- **创建溯源任务**：验证 KillChain 分析

---

## 客户机信息

| 客户机 | 端口 | 主机类型 | 攻击场景 | 事件数 |
|--------|------|----------|----------|--------|
| client1 | 8888 | Web 服务器 | SQL 注入 + Webshell + 提权 + C2 | ~20 |
| client2 | 8889 | 数据库服务器 | SSH 暴力破解 + 恶意 SQL + 数据导出 | ~15 |
| client3 | 8890 | 文件服务器 | FTP 暴力破解 + 恶意文件 + 数据窃取 | ~18 |
| client4 | 8891 | 内网跳板机 | 横向移动 + 侦察 + 隐蔽 C2 | ~22 |

**总计**：~75 个事件，覆盖 8 个 MITRE ATT&CK 战术

---

## 攻击场景详解

### 客户机 1：Web 服务器（web-server-001）

1. **SQL 注入**（TA0001 T1190）- Suricata 检测到 5 次 SQL 注入尝试
2. **Webshell 执行**（TA0002 T1505.003）- PHP webshell 执行多个命令
3. **提权到 root**（TA0004 T1548.003）- sudo 提权
4. **C2 通信**（TA0011 T1071.001）- 5 次 HTTP 心跳连接

### 客户机 2：数据库服务器（db-server-001）

1. **SSH 暴力破解**（TA0001 T1110.001）- 5 次失败登录后成功
2. **恶意 SQL**（TA0002 T1055）- 执行 SQL 注入和修改
3. **数据导出**（TA0009 T1005）- mysqldump 导出敏感数据
4. **数据删除**（TA0010 T1565.001）- 删除数据库文件

### 客户机 3：文件服务器（file-server-001）

1. **FTP 暴力破解**（TA0001 T1110.001）- 4 次失败登录后成功
2. **上传恶意文件**（TA0002 T1505.003）- 上传 Python webshell
3. **服务持久化**（TA0003 T1543.002）- 启用恶意服务
4. **数据窃取**（TA0009 T1041）- scp 传输 4 个敏感文件

### 客户机 4：内网跳板机（pivot-server-001）

1. **内网扫描**（TA0007 T1018）- 5 次 ICMP ping 扫描内网
2. **侦察活动**（TA0007 T1018）- nmap 扫描内网主机
3. **SSH 横向移动**（TA0008 T1021.001）- 登录 victim-01 和 victim-02
4. **DNS 隧道**（TA0011 T1071.004）- 6 次 DNS 查询建立隐蔽 C2 通道

---

## 查看日志

实时查看日志：
```bash
# 客户机 1
tail -f client1.log

# 客户机 2
tail -f client2.log

# 客户机 3
tail -f client3.log

# 客户机 4
tail -f client4.log
```

查看轮询状态：
```bash
# 确认客户机已注册
grep "注册成功" client*.log

# 查看轮询请求
grep "返回.*条.*事件" client*.log
```

---

## 停止测试

### 方式 1：使用保存的 PID
```bash
kill $(cat .client_pids.txt)
```

### 方式 2：使用 pkill
```bash
pkill -f 'client[1-4].py'
```

### 方式 3：手动查找并停止
```bash
# 查看运行的客户机进程
ps aux | grep "client[1-4].py"

# 停止进程
kill <PID>
```

---

## 用户检测清单

使用前端界面检测以下内容：

### 1. 事件查询验证
- [ ] 查询 Web 服务器（web-server-001）的 SQL 注入事件
- [ ] 查询数据库服务器（db-server-001）的暴力破解事件
- [ ] 查询文件服务器（file-server-001）的恶意文件事件
- [ ] 查询跳板机（pivot-server-001）的横向移动事件

### 2. 图谱可视化验证
- [ ] 查看攻击路径是否包含所有阶段
- [ ] 验证节点之间的关系（Process → Host → File）
- [ ] 验证边的属性（是否包含 threat.tactic.id）

### 3. KillChain 分析验证
- [ ] 创建溯源任务（选择任意节点）
- [ ] 等待任务完成（status: "succeeded"）
- [ ] 查看 KillChain 面板
- [ ] 验证 segments 是否正确分段
- [ ] 验证 explanation 是否生成
- [ ] 验证 confidence 是否合理（0.0-1.0）

### 4. 报告导出验证（可选）
- [ ] 导出溯源报告
- [ ] 验证 KillChain 数据是否包含在报告中

---

## 文件说明

- **apt_data.py** - APT 攻击数据生成器（共享模块）
- **client1.py** - 客户机 1（Web 服务器）
- **client2.py** - 客户机 2（数据库服务器）
- **client3.py** - 客户机 3（文件服务器）
- **client4.py** - 客户机 4（内网跳板机）
- **start_clients.sh** - 启动脚本
- **README.md** - 本文档

---

## 客户机职责（重要）

### ✅ 客户机只做的事情
- 提供三个接口：`/falco`, `/filebeat`, `/suricata`
- 启动时自动注册到中心机
- 被动等待轮询，返回数据
- 数据加载完成后打印日志

### ❌ 客户机不做的事情
- 不主动触发检测
- 不修改数据库
- 不做结果验证
- 不调用中心机的任何 API（除了注册）

---

## 故障排查

### 客户机启动失败
```bash
# 检查端口占用
lsof -i :8888
lsof -i :8889
lsof -i :8890
lsof -i :8891

# 停止占用端口的进程
kill <PID>
```

### 中心机无法轮询
```bash
# 检查中心机是否运行
curl http://localhost:8001/health

# 检查客户机是否注册成功
grep "注册" client*.log

# 检查网络连接
curl http://localhost:8888/falco
curl http://localhost:8889/falco
curl http://localhost:8890/falco
curl http://localhost:8891/falco
```

### 数据未入库
```bash
# 查看中心机日志
cd backend
tail -f logs/center_machine.log

# 查看 OpenSearch 索引
curl -X GET "localhost:9200/_cat/indices?v"
```

---

## 技术细节

### ECS 规范
- **event.id**: `evt-` + 16 位十六进制（SHA1 哈希）
- **@timestamp**: ISO 8601 格式（UTC 时区）
- **event.kind**: "event" 或 "alert"
- **event.dataset**: 数据集标识（如 "falco.syscall"）
- **host.id**: 主机唯一标识符
- **host.name**: 主机名称

### MITRE ATT&CK 字段
- **threat.tactic.id**: 战术 ID（如 TA0001）
- **threat.technique.id**: 技术 ID（如 T1190）
- **threat.tactic.reference**: ATT&CK 官方链接

### 数据来源
- **Falco**: 系统调用和进程事件
- **Filebeat**: 系统日志和认证事件
- **Suricata**: 网络流量和 IDS 告警
