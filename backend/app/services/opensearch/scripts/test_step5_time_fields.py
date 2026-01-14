#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 5：三时间字段处理测试"""
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
from app.services.opensearch.client import get_client
from app.services.opensearch.index import INDEX_PATTERNS, get_index_name

if __name__ == '__main__':
    print("=" * 60)
    print("步骤 5：三时间字段处理测试")
    print("=" * 60)
    
    # 测试：缺失 event.created，应该回填为 @timestamp
    test_event = {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event": {
            "id": "test-time-001",
            "kind": "event",
            "dataset": "hostlog.auth"
            # 故意不写 created
        },
        "host": {"id": "h-test-001", "name": "test-host"},
        "message": "Test time fields"
    }
    
    print("\n写入测试数据（缺失 event.created）...")
    result = store_events([test_event])
    print(f"写入结果: 成功={result['success']}, 失败={result['failed']}")
    
    if result['success'] == 0:
        print("✗ 写入失败，无法继续验证")
        sys.exit(1)
    
    # 验证三时间字段
    print("\n验证三时间字段...")
    client = get_client()
    today = datetime.now()
    index_name = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    doc = client.get(index=index_name, id='test-time-001')['_source']
    
    timestamp = doc.get('@timestamp')
    event_created = doc.get('event', {}).get('created')
    event_ingested = doc.get('event', {}).get('ingested')
    
    print(f"\n@timestamp: {timestamp}")
    print(f"event.created: {event_created}")
    print(f"event.ingested: {event_ingested}")
    
    # 验证
    checks = []
    
    if timestamp:
        checks.append(("@timestamp 存在", True))
    else:
        checks.append(("@timestamp 存在", False))
    
    if event_created:
        checks.append(("event.created 存在", True))
        if event_created == timestamp:
            checks.append(("event.created 等于 @timestamp", True))
        else:
            checks.append(("event.created 等于 @timestamp", False))
    else:
        checks.append(("event.created 存在", False))
        checks.append(("event.created 等于 @timestamp", False))
    
    if event_ingested:
        checks.append(("event.ingested 存在", True))
    else:
        checks.append(("event.ingested 存在", False))
    
    print("\n" + "=" * 60)
    all_passed = all(check[1] for check in checks)
    for check_name, passed in checks:
        status = "✓" if passed else "✗"
        print(f"{status} {check_name}")
    
    if all_passed:
        print("\n✓ 三时间字段处理测试通过")
    else:
        print("\n✗ 三时间字段处理测试失败")
    print("=" * 60)
