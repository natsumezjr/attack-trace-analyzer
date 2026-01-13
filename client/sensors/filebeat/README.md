# Ubuntu 日志异常检测系统

基于 Filebeat + Sigma 规则的实时日志异常检测系统，支持 Docker 容器化部署和原生 Linux 安装。

## 系统架构

```
Ubuntu 系统日志 → Filebeat → ECS 格式 → Python 检测器 → 异常标记
(/var/log/*)      (8.11)    (JSON)      (Sigma 规则)    (数据库+JSON)
```

**核心组件：**
- **Filebeat 8.11**：轻量级日志采集工具，实时读取系统日志并转换为 ECS 标准格式
- **Sigma 规则引擎**：41 条行业标准检测规则，覆盖 MITRE ATT&CK 框架
- **Python 检测器**：实时分析引擎，标记异常并存储到数据库
- **SQLite 数据库**：永久存储所有日志数据
- **JSON 缓存**：临时缓存最近 5 分钟的日志（定期清理）

**监控日志：**
- `/var/log/auth.log` - 认证日志（SSH、sudo、PAM）
- `/var/log/syslog` - 系统日志（进程、服务、网络）
- `/var/log/kern.log` - 内核日志（模块、驱动、硬件）

## 文件架构

```
filebeat/
├── README.md                    # 项目说明文档
├── requirements.txt             # Python 依赖包列表
│
├── detector.py                  # 核心检测引擎（实时监控+规则匹配）
│
├── docker-start.sh              # Docker 一键启动脚本
├── docker-compose.yml           # Docker 编排配置
├── Dockerfile                   # Docker 镜像构建文件
├── docker-entrypoint.sh         # 容器启动入口脚本
│
├── start_detection.sh           # Linux 原生一键启动脚本
│
├── filebeat.yml                 # Filebeat 配置（原生安装）
├── filebeat-docker.yml          # Filebeat 配置（Docker）
│
├── rules/                       # Sigma 检测规则目录（41 个规则）
│   ├── failed_ssh_auth.yml              # SSH 暴力破解检测（高危）
│   ├── sudo_escalation.yml              # Sudo 权限提升检测（中危）
│   ├── suid_execution.yml               # SUID 程序执行检测（高危）
│   ├── ssh_keys_modification.yml        # SSH 密钥修改检测（高危）
│   ├── kernel_module_loading.yml        # 内核模块加载检测（高危）
│   ├── dns_tunneling.yml                # DNS 隧道检测（高危）
│   ├── port_scanning.yml                # 端口扫描检测（中危）
│   ├── webshell_detection.yml           # Webshell 检测（高危）
│   ├── docker_escape.yml                # Docker 容器逃逸检测（高危）
│   ├── log_tampering.yml                # 日志篡改检测（高危）
│   └── ... （共 41 个规则）
│
└── output/                      # 检测输出目录（运行时自动创建）
    ├── detection_results.db             # SQLite 数据库（永久存储）
    ├── ecs_logs_with_anomalies.json     # 临时缓存：所有日志（5 分钟）
    └── anomalies.json                   # 临时缓存：仅异常日志（5 分钟）
```

### 核心文件说明

| 文件 | 作用 |
|------|------|
| `detector.py` | 检测引擎核心代码，负责加载规则、监控日志、匹配异常、写入数据库 |
| `docker-start.sh` | Docker 一键启动脚本，自动检查环境、构建镜像、启动容器 |
| `start_detection.sh` | Linux 原生一键启动脚本，自动配置 Filebeat、启动检测器 |
| `filebeat.yml` | Filebeat 配置文件，定义日志源路径和输出格式 |
| `docker-compose.yml` | Docker 编排配置，定义容器、卷挂载、网络设置 |
| `requirements.txt` | Python 依赖：PyYAML（解析规则）、watchdog（文件监控） |

### 检测规则分类（41 个）

**认证类（3 个）**
- SSH 暴力破解、密码修改、PAM 认证绕过

**权限提升类（5 个）**
- Sudo 提权、SUID 执行、Sudoers 修改、Capabilities 操纵、切换到 root

**持久化类（5 个）**
- SSH 密钥修改、RC 脚本修改、内核模块加载、Systemd 服务创建、Cron 持久化

**网络类（5 个）**
- DNS 隧道、SSH 隧道、端口扫描、可疑出站连接、防火墙修改

**文件/进程类（8 个）**
- 隐藏文件创建、压缩工具使用、敏感文件访问、文件删除、可疑进程执行、反弹 Shell、服务篡改

**系统配置类（8 个）**
- Hosts 文件修改、包管理器滥用、安全模块禁用、LD_PRELOAD 劫持、时间修改、日志篡改、用户账户创建

**高级威胁类（5 个）**
- Docker 容器逃逸、数据库访问、Webshell 检测、Shell 历史访问、内存转储

## 一键启动指令

### 方式一：Docker 部署（推荐）

**适用环境：** Windows（Docker Desktop）、Linux、macOS

#### Windows 环境

**前提条件：** 安装 Docker Desktop for Windows

```powershell
# 进入项目目录
cd filebeat

# 启动容器（首次会自动构建镜像，需要几分钟）
docker compose up

# 或后台运行
docker compose up -d

# 查看日志
docker logs -f filebeat-log-detector-1

# 停止容器
docker compose down
```

**强制重建镜像**（代码更新后）：
```powershell
# 方式 1：重建并启动
docker compose up --build

# 方式 2：完全重建（不使用缓存）
docker compose build --no-cache
docker compose up

# 方式 3：重建 + 强制重新创建容器
docker compose up --build --force-recreate
```

#### Linux/macOS 环境（使用 Shell 脚本）

```bash
# 进入项目目录
cd filebeat

# 赋予执行权限
chmod +x docker-start.sh

# 一键启动
./docker-start.sh

# 强制重建
./docker-start.sh --rebuild
```

**脚本功能：**
1. ✓ 检查 Docker 环境
2. ✓ 清理旧容器
3. ✓ 智能检查镜像（存在则复用，不存在才构建）
4. ✓ 清理旧的 JSON 输出文件
5. ✓ 启动容器并显示实时日志

---

### 方式二：Linux 原生部署

**适用环境：** Ubuntu/Debian Linux 系统

**前提条件：**
```bash
# 安装 Filebeat 8.11
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-amd64.deb
sudo dpkg -i filebeat-8.11.0-amd64.deb

# 安装 Python 3 和依赖
sudo apt-get update
sudo apt-get install python3 python3-pip -y
pip3 install -r requirements.txt

# 复制 Filebeat 配置
sudo cp filebeat.yml /etc/filebeat/filebeat.yml
sudo chmod 644 /etc/filebeat/filebeat.yml
```

**一键启动：**
```bash
# 进入项目目录
cd filebeat

# 赋予执行权限
chmod +x start_detection.sh

# 一键启动
./start_detection.sh
```

**脚本功能：**
1. ✓ 停止所有旧的 Filebeat 进程
2. ✓ 修复配置文件权限
3. ✓ 清理旧的 JSON 输出文件
4. ✓ 后台启动 Filebeat
5. ✓ 启动异常检测器
6. ✓ 按 Ctrl+C 停止时自动清理所有进程和 JSON 文件

**手动启动（不推荐）：**
```bash
# 启动 Filebeat
sudo systemctl start filebeat
sudo systemctl enable filebeat

# 启动检测器
python3 detector.py
```

## 数据管理策略

### JSON 缓存（临时，5 分钟）
- **位置**：`output/ecs_logs_with_anomalies.json`, `output/anomalies.json`
- **用途**：快速查看最近的检测结果
- **清理策略**：
  - 启动时：清空旧文件
  - 运行中：每 1 分钟自动删除 5 分钟前的记录
  - 退出时：清空所有 JSON 文件

### SQLite 数据库（永久）
- **位置**：`output/detection_results.db`
- **用途**：永久存储所有日志数据（包括正常日志和异常日志）
- **表结构**：
  ```sql
  CREATE TABLE data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_json TEXT  -- 完整的 ECS 格式 JSON 字符串
  );
  ```

### 查询数据库

```bash
# 打开数据库
sqlite3 output/detection_results.db

# 统计总记录数
SELECT COUNT(*) FROM data;

# 查看最近 10 条记录
SELECT id,
       json_extract(event_json, '$.@timestamp') as timestamp,
       json_extract(event_json, '$.message') as message
FROM data
ORDER BY id DESC
LIMIT 10;

# 仅查看异常记录
SELECT id,
       json_extract(event_json, '$.@timestamp') as timestamp,
       json_extract(event_json, '$.anomaly.matched_rules[0].rule_title') as rule_name,
       json_extract(event_json, '$.anomaly.matched_rules[0].severity') as severity
FROM data
WHERE json_extract(event_json, '$.anomaly.detected') = 1;
```

## 测试检测

启动系统后，在终端执行以下命令触发检测：

```bash
# SSH 失败（触发 SSH 暴力破解检测）
ssh wronguser@localhost

# Sudo 操作（触发权限提升检测）
sudo ls

# 创建用户（触发账户创建检测）
sudo useradd testuser123

# 服务操作（触发服务篡改检测）
sudo systemctl restart cron

# 访问敏感文件（触发敏感文件访问检测）
cat /etc/shadow
```

查看检测结果：
```bash
# 查看最近的异常日志（JSON 缓存）
tail -f output/anomalies.json

# 查询数据库中的异常记录
sqlite3 output/detection_results.db "SELECT * FROM data WHERE json_extract(event_json, '$.anomaly.detected') = 1;"
```

## 输出格式

### 异常日志示例

```json
{
  "@timestamp": "2026-01-13T10:30:45.123Z",
  "message": "sshd[1234]: Failed password for invalid user admin from 192.168.1.100",
  "log_type": "auth",
  "event": {
    "kind": "alert",
    "category": ["intrusion_detection"],
    "type": ["indicator"]
  },
  "anomaly": {
    "detected": true,
    "detection_timestamp": "2026-01-13T10:30:46.789Z",
    "matched_rules": [
      {
        "rule_id": "afb8f1a9-7a4b-4c8a-9e3d-1a2b3c4d5e6f",
        "rule_title": "Multiple Failed SSH Authentication Attempts",
        "severity": "high",
        "tags": ["attack.credential_access", "attack.t1110"]
      }
    ],
    "rule_count": 1
  },
  "threat": {
    "indicator": {
      "description": "Detects multiple failed SSH authentication attempts",
      "severity": "high"
    }
  }
}
```

## 添加自定义规则

1. 在 `rules/` 目录创建新的 `.yml` 文件
2. 遵循 Sigma 规则格式：

```yaml
title: 规则名称
id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
status: stable
description: 规则描述
references:
  - https://attack.mitre.org/techniques/TXXXX/
author: Security Team
date: 2024/01/01
logsource:
  product: linux
  service: syslog
detection:
  selection:
    - message|contains: '关键字1'
    - message|contains: '关键字2'
  condition: selection
falsepositives:
  - 正常行为描述
level: high  # critical, high, medium, low
tags:
  - attack.tactic_name
  - attack.tXXXX
```

3. 重启检测器即可自动加载新规则

## 性能指标

- **内存占用**：~50MB（Python 检测器）
- **CPU 占用**：<5%（典型工作负载）
- **处理速度**：~1000 条日志/秒
- **磁盘占用**：SQLite 数据库随日志量增长

## 故障排查

### Docker 模式

```powershell
# 查看容器状态
docker ps -a

# 查看容器日志
docker logs filebeat-log-detector-1

# 进入容器调试
docker exec -it filebeat-log-detector-1 /bin/bash

# 检查 Filebeat 状态
docker exec filebeat-log-detector-1 ps aux | grep filebeat
```

### Linux 原生模式

```bash
# 检查 Filebeat 状态
sudo systemctl status filebeat
sudo journalctl -u filebeat -n 50

# 检查输出目录
ls -lh output/

# 检查日志文件权限
ls -l /var/log/auth.log /var/log/syslog /var/log/kern.log
```

## 参考资料

- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Filebeat 文档](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Sigma 规则仓库](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK 框架](https://attack.mitre.org/)

## 许可证

- Filebeat: Apache 2.0 License
- Sigma Rules: Detection Rule License (DRL) 1.1
- Python 代码: MIT License
