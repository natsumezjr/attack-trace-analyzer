#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 3：数据写入测试"""
import sys
import os
from datetime import datetime, timezone

# 添加项目路径：从 scripts/ 目录向上找到 backend/ 目录
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

# 将 backend/ 目录添加到路径，这样就可以导入 app.services.opensearch
sys.path.insert(0, backend_dir)

from app.services.opensearch.storage import store_events

if __name__ == '__main__':
    print("=" * 60)
    print("步骤 3：数据写入测试")
    print("=" * 60)
    
    # 创建测试 Telemetry 数据
    test_event = {
        "ecs": {"version": "9.2.0"},
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event": {
            "id": "test-evt-001",
            "kind": "event",
            "dataset": "hostlog.auth",
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "category": ["authentication"],
            "action": "user_login"
        },
        "host": {"id": "h-test-001", "name": "test-host"},
        "user": {"name": "testuser"},
        "source": {"ip": "192.168.1.100"},
        "message": "Test authentication event"
    }
    
    print("\n写入测试数据...")
    result = store_events([test_event])
    
    print("\n写入结果:")
    print(f"  成功: {result['success']}")
    print(f"  失败: {result['failed']}")
    print(f"  重复: {result['duplicated']}")
    
    if result['success'] == 1 and result['failed'] == 0:
        print("\n✓ 数据写入测试通过")
    else:
        print("\n✗ 数据写入测试失败")
        print(f"  详情: {result}")
