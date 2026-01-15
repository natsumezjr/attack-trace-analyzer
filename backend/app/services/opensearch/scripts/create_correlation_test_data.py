#!/usr/bin/env python3
"""
创建 Correlation Rules 测试数据（Event 数据）

功能：
1. 生成横向移动攻击链的测试数据（原始 events）
2. 包含3个阶段的 events：
   - 主机A上的提权行为（Privilege Escalation）- Query1
   - 从A到B的远程连接/登录（Remote Connect/Logon）- Query2
   - 主机B上的提权或远程执行行为（Privilege Escalation / Remote Execution）- Query3
3. 写入到 ecs-events 索引

使用方法:
    uv run python create_correlation_test_data.py
"""

import sys
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.services.opensearch.client import bulk_index, refresh_index, index_exists
from app.core.time import utc_now_rfc3339, to_rfc3339


def create_privilege_escalation_event(
    host_id: str,
    host_name: str,
    user_name: str,
    base_time: datetime,
    use_suspicious_parent: bool = False
) -> dict:
    """
    创建提权事件（Query1 和 Query3 匹配）
    
    参数：
    - host_id: 主机ID
    - host_name: 主机名
    - user_name: 用户名
    - base_time: 基准时间
    - use_suspicious_parent: 是否使用可疑父进程（Level 2）
    
    返回: event dict
    """
    timestamp = to_rfc3339(base_time)
    
    # 可疑父进程列表
    suspicious_parents = ["chrome.exe", "firefox.exe", "outlook.exe"]
    
    # 提权相关的进程名和命令行
    if use_suspicious_parent:
        # Level 2: 从可疑父进程启动
        process_name = "runas.exe"
        command_line = "runas /user:admin cmd.exe"
        parent_name = suspicious_parents[0]  # chrome.exe
    else:
        # Level 1: 包含提权关键词
        process_name = "privilege-escalator.exe"
        command_line = "privilege-escalator.exe --elevate"
        parent_name = "explorer.exe"
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp,
        "event": {
            "id": f"event-privesc-{uuid.uuid4().hex[:8]}",
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_start",
            "dataset": "windows",
            "created": timestamp,
            "ingested": timestamp,
        },
        "host": {
            "id": host_id,
            "name": host_name
        },
        "user": {
            "id": f"user-{user_name}",
            "name": user_name
        },
        "process": {
            "entity_id": f"proc-{uuid.uuid4().hex[:8]}",
            "pid": 1234,
            "name": process_name,
            "command_line": command_line,
            "parent": {
                "pid": 1000,
                "name": parent_name,
                "executable": f"C:\\Windows\\System32\\{parent_name}"
            }
        },
        "message": f"Process started: {process_name} on {host_name}"
    }


def create_network_connection_event(
    host_id: str,
    host_name: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    base_time: datetime
) -> dict:
    """
    创建网络连接事件（Query2 匹配）
    
    参数：
    - host_id: 源主机ID
    - host_name: 源主机名
    - src_ip: 源IP
    - dst_ip: 目标IP
    - src_port: 源端口
    - dst_port: 目标端口
    - base_time: 基准时间
    
    返回: event dict
    """
    timestamp = to_rfc3339(base_time)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp,
        "event": {
            "id": f"event-network-{uuid.uuid4().hex[:8]}",
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "network_connection",
            "dataset": "network",
            "created": timestamp,
            "ingested": timestamp,
        },
        "host": {
            "id": host_id,
            "name": host_name
        },
        "source": {
            "ip": src_ip,
            "port": src_port
        },
        "destination": {
            "ip": dst_ip,
            "port": dst_port
        },
        "network": {
            "transport": "tcp",
            "direction": "outbound"
        },
        "message": f"Network connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
    }


def create_authentication_event(
    host_id: str,
    host_name: str,
    user_name: str,
    src_ip: str,
    base_time: datetime
) -> dict:
    """
    创建认证事件（Query3 匹配 - 远程登录）
    
    参数：
    - host_id: 目标主机ID
    - host_name: 目标主机名
    - user_name: 用户名
    - src_ip: 源IP（登录来源）
    - base_time: 基准时间
    
    返回: event dict
    """
    timestamp = to_rfc3339(base_time)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp,
        "event": {
            "id": f"event-auth-{uuid.uuid4().hex[:8]}",
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
            "action": "user_login",
            "dataset": "windows",
            "created": timestamp,
            "ingested": timestamp,
        },
        "host": {
            "id": host_id,
            "name": host_name
        },
        "user": {
            "id": f"user-{user_name}",
            "name": user_name
        },
        "source": {
            "ip": src_ip
        },
        "message": f"User {user_name} logged in from {src_ip} to {host_name}"
    }


def create_lateral_movement_chain_events(
    host_a: str = "host-001",
    host_b: str = "host-002",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.200",
    user_name: str = "admin",
    base_time: datetime = None,
    use_suspicious_parent: bool = False
) -> list[dict]:
    """
    创建横向移动攻击链的测试 events
    
    参数：
    - host_a: 主机A的ID
    - host_b: 主机B的ID
    - src_ip: 源IP（主机A的IP）
    - dst_ip: 目标IP（主机B的IP）
    - user_name: 用户名
    - base_time: 基准时间（默认：当前时间）
    - use_suspicious_parent: 是否使用可疑父进程（Level 2）
    
    返回: List[event] 包含3个阶段的 events
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc)
    
    events = []
    
    # ========== Event 1: 主机A上的提权行为（Query1 匹配）==========
    event_1 = create_privilege_escalation_event(
        host_id=host_a,
        host_name=f"server-{host_a.split('-')[-1]}",
        user_name=user_name,
        base_time=base_time,
        use_suspicious_parent=use_suspicious_parent
    )
    events.append(event_1)
    
    # ========== Event 2: 从A到B的远程连接事件（Query2 匹配）==========
    # 时间：5分钟后
    event_2_time = base_time + timedelta(minutes=5)
    event_2 = create_network_connection_event(
        host_id=host_a,
        host_name=f"server-{host_a.split('-')[-1]}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=3389,
        dst_port=3389,
        base_time=event_2_time
    )
    events.append(event_2)
    
    # ========== Event 3: 主机B上的提权或远程执行行为（Query3 匹配）==========
    # 时间：10分钟后
    event_3_time = base_time + timedelta(minutes=10)
    
    # 可以选择生成提权事件或认证事件（都匹配 Query3）
    # 这里生成提权事件
    event_3 = create_privilege_escalation_event(
        host_id=host_b,
        host_name=f"server-{host_b.split('-')[-1]}",
        user_name=user_name,
        base_time=event_3_time,
        use_suspicious_parent=False
    )
    events.append(event_3)
    
    # 可选：也可以添加认证事件
    # event_3_auth = create_authentication_event(
    #     host_id=host_b,
    #     host_name=f"server-{host_b.split('-')[-1]}",
    #     user_name=user_name,
    #     src_ip=src_ip,
    #     base_time=event_3_time
    # )
    # events.append(event_3_auth)
    
    return events


def create_isolated_event(
    host: str = "host-999",
    base_time: datetime = None
) -> dict:
    """
    创建一个孤立的事件（不与其他 events 关联，用于测试过滤）
    
    参数：
    - host: 主机ID
    - base_time: 基准时间
    
    返回: event dict
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    
    timestamp = to_rfc3339(base_time)
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp,
        "event": {
            "id": f"event-isolated-{uuid.uuid4().hex[:8]}",
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_start",
            "dataset": "windows",
            "created": timestamp,
            "ingested": timestamp,
        },
        "host": {
            "id": host,
            "name": f"server-{host.split('-')[-1]}"
        },
        "process": {
            "entity_id": f"proc-{uuid.uuid4().hex[:8]}",
            "pid": 9999,
            "name": "notepad.exe",
            "command_line": "notepad.exe"
        },
        "message": f"Isolated process event on {host}"
    }


def create_multiple_chains(
    num_chains: int = 2,
    base_time: datetime = None,
    include_isolated: bool = True
) -> list[dict]:
    """
    创建多个横向移动攻击链
    
    参数：
    - num_chains: 要创建的链数量
    - base_time: 基准时间（默认：当前时间往前推，确保有时间差）
    - include_isolated: 是否包含孤立的事件（用于测试过滤）
    
    返回: List[event] 包含所有链的 events
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    
    all_events = []
    
    for i in range(num_chains):
        # 每个链使用不同的主机和IP
        host_a = f"host-{100 + i:03d}"
        host_b = f"host-{200 + i:03d}"
        src_ip = f"192.168.1.{100 + i}"
        dst_ip = f"192.168.1.{200 + i}"
        user_name = f"user-{i + 1}"
        
        # 每个链的时间稍微错开
        chain_base_time = base_time + timedelta(minutes=i * 2)
        
        # 第一个链使用可疑父进程（Level 2），其他使用普通提权（Level 1）
        use_suspicious_parent = (i == 0)
        
        chain_events = create_lateral_movement_chain_events(
            host_a=host_a,
            host_b=host_b,
            src_ip=src_ip,
            dst_ip=dst_ip,
            user_name=user_name,
            base_time=chain_base_time,
            use_suspicious_parent=use_suspicious_parent
        )
        
        all_events.extend(chain_events)
    
    # 添加一些孤立的事件（用于测试过滤）
    if include_isolated:
        for i in range(2):
            isolated_time = base_time + timedelta(minutes=i * 3)
            isolated = create_isolated_event(
                host=f"host-{999 + i:03d}",
                base_time=isolated_time
            )
            all_events.append(isolated)
    
    return all_events


def main():
    """主函数"""
    print("=" * 80)
    print("创建 Correlation Rules 测试数据（Event 数据）")
    print("=" * 80)
    
    client = get_client()
    today = datetime.now(timezone.utc)
    events_index_name = get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
    
    # 确保索引存在
    if not index_exists(events_index_name):
        print(f"\n[INFO] 创建索引: {events_index_name}")
        from app.services.opensearch.index import initialize_indices
        initialize_indices()
    
    # 创建测试数据
    print(f"\n[1] 生成横向移动攻击链测试数据（Events）...")
    events = create_multiple_chains(num_chains=2)
    print(f"    生成了 {len(events)} 个 events（2个攻击链，每个链3个阶段）")
    
    # 显示生成的 events 摘要
    print(f"\n[2] Events 摘要:")
    for i, event in enumerate(events, 1):
        event_id = event.get("event", {}).get("id", "unknown")
        event_category = event.get("event", {}).get("category", [])
        event_action = event.get("event", {}).get("action", "unknown")
        host_id = event.get("host", {}).get("id", "unknown")
        timestamp = event.get("@timestamp", "unknown")
        print(f"    [{i}] {event_id}")
        print(f"        Category: {event_category}, Action: {event_action}, Host: {host_id}, Time: {timestamp}")
    
    # 写入索引
    print(f"\n[3] 写入 ECS Events 索引: {events_index_name}")
    documents = [
        {
            "id": event.get("event", {}).get("id"),
            "document": event
        }
        for event in events
    ]
    
    try:
        result = bulk_index(events_index_name, documents)
        
        if result.get("success", 0) > 0:
            refresh_index(events_index_name)
            print(f"    ✓ 成功写入 {result.get('success', 0)} 个 events")
            
            if result.get("failed", 0) > 0:
                print(f"    ⚠ 失败: {result.get('failed', 0)} 个 events")
                if result.get("errors"):
                    for error in result.get("errors", [])[:5]:  # 只显示前5个错误
                        print(f"      错误: {error}")
        else:
            print(f"    ✗ 写入失败")
            if result.get("errors"):
                for error in result.get("errors", [])[:5]:
                    print(f"      错误: {error}")
        
        # 验证写入
        print(f"\n[4] 验证写入结果...")
        count_response = client.count(index=events_index_name)
        total_count = count_response.get('count', 0)
        print(f"    索引中共有 {total_count} 个 events")
        
        print(f"\n[5] 测试数据创建完成！")
        print(f"\n下一步：")
        print(f"  1. 运行 correlation 分析:")
        print(f"     from app.services.opensearch.analysis import run_data_analysis")
        print(f"     run_data_analysis()")
        print(f"  2. 查看生成的横向移动 findings:")
        print(f"     uv run python show_raw_findings.py")
        
    except Exception as e:
        print(f"\n[ERROR] 写入失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
