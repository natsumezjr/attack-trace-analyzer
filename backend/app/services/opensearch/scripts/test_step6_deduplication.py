#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 6：幂等去重测试"""
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
    print("步骤 6：幂等去重测试")
    print("=" * 60)
    
    # 创建相同 event.id 的两个事件
    event1 = {
        "ecs": {"version": "9.2.0"},
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event": {
            "id": "test-dup-001",
            "kind": "event",
            "dataset": "hostlog.auth",
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        },
        "host": {"id": "h-test-001", "name": "test-host"},
        "message": "First write"
    }
    
    event2 = {
        "ecs": {"version": "9.2.0"},
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event": {
            "id": "test-dup-001",  # 相同的 ID
            "kind": "event",
            "dataset": "hostlog.auth",
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        },
        "host": {"id": "h-test-001", "name": "test-host"},
        "message": "Second write (should be deduplicated)"
    }
    
    print("\n第一次写入（event.id: test-dup-001）...")
    result1 = store_events([event1])
    print(f"  成功: {result1['success']}, 失败: {result1['failed']}, 重复: {result1['duplicated']}")
    
    print("\n第二次写入（相同的 event.id: test-dup-001）...")
    result2 = store_events([event2])
    print(f"  成功: {result2['success']}, 失败: {result2['failed']}, 重复: {result2['duplicated']}")
    
    print("\n" + "=" * 60)
    # 验证：第一次应该成功，第二次应该被去重
    if result1['success'] == 1 and result1['duplicated'] == 0:
        print("✓ 第一次写入成功")
    else:
        print("✗ 第一次写入失败")
    
    if result2['success'] == 0 and result2['duplicated'] == 1:
        print("✓ 第二次写入被正确去重")
    else:
        print("✗ 第二次写入去重失败")
        print(f"  预期: success=0, duplicated=1")
        print(f"  实际: success={result2['success']}, duplicated={result2['duplicated']}")
    
    if result1['success'] == 1 and result1['duplicated'] == 0 and result2['success'] == 0 and result2['duplicated'] == 1:
        print("\n✓ 幂等去重测试通过")
    else:
        print("\n✗ 幂等去重测试失败")
    print("=" * 60)
