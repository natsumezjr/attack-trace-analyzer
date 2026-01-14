#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 4：路由规则测试"""
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

from app.services.opensearch.storage import route_to_index

if __name__ == '__main__':
    print("=" * 60)
    print("步骤 4：路由规则测试")
    print("=" * 60)
    
    # 测试1: Telemetry (event.kind="event")
    telemetry = {
        "event": {"kind": "event", "dataset": "hostlog.process"},
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    route1 = route_to_index(telemetry)
    print(f"\n测试1 - Telemetry 路由: {route1}")
    print(f"  预期: ecs-events-YYYY-MM-DD")
    print(f"  结果: {'✓ 正确' if 'ecs-events' in route1 else '✗ 错误'}")
    
    # 测试2: Raw Finding (event.kind="alert", dataset != "finding.canonical")
    raw_finding = {
        "event": {"kind": "alert", "dataset": "finding.raw.falco"},
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    route2 = route_to_index(raw_finding)
    print(f"\n测试2 - Raw Finding 路由: {route2}")
    print(f"  预期: raw-findings-YYYY-MM-DD")
    print(f"  结果: {'✓ 正确' if 'raw-findings' in route2 else '✗ 错误'}")
    
    # 测试3: Canonical Finding (event.kind="alert", dataset="finding.canonical")
    canonical_finding = {
        "event": {"kind": "alert", "dataset": "finding.canonical"},
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    route3 = route_to_index(canonical_finding)
    print(f"\n测试3 - Canonical Finding 路由: {route3}")
    print(f"  预期: canonical-findings-YYYY-MM-DD")
    print(f"  结果: {'✓ 正确' if 'canonical-findings' in route3 else '✗ 错误'}")
    
    print("\n" + "=" * 60)
    if 'ecs-events' in route1 and 'raw-findings' in route2 and 'canonical-findings' in route3:
        print("✓ 路由规则测试全部通过")
    else:
        print("✗ 路由规则测试失败")
    print("=" * 60)
