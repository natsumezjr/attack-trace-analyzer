#!/usr/bin/env python3
"""
测试Query 2的NOT端口条件解析

验证NOT (destination.port:80 OR destination.port:443 OR destination.port:8080 OR destination.port:8443)是否正确解析
"""

import sys
import re
from pathlib import Path

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.analysis import _query_string_to_dsl
from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.services.opensearch.client import refresh_index
from datetime import datetime, timezone

def test_not_ports_parsing():
    """测试NOT端口条件解析"""
    query_string = (
        "event.category:network AND "
        "_exists_:source.ip AND "
        "_exists_:destination.ip AND "
        "_exists_:host.name AND "
        "network.direction:outbound AND "
        "NOT (destination.port:80 OR destination.port:443 OR destination.port:8080 OR destination.port:8443)"
    )
    
    print("=" * 80)
    print("测试Query 2的NOT端口条件解析")
    print("=" * 80)
    
    print(f"\n查询条件: {query_string}")
    
    dsl_query = _query_string_to_dsl(query_string)
    
    print(f"\n转换后的DSL查询:")
    import json
    print(json.dumps(dsl_query, indent=2, ensure_ascii=False))
    
    # 检查must_not子句
    must_not = dsl_query.get('bool', {}).get('must_not', [])
    print(f"\nMust Not子句数量: {len(must_not)}")
    
    for i, clause in enumerate(must_not, 1):
        print(f"\nMust Not {i}:")
        print(json.dumps(clause, indent=2, ensure_ascii=False))
    
    # 测试查询
    print("\n" + "=" * 80)
    print("测试实际查询")
    print("=" * 80)
    
    client = get_client()
    today = datetime.now(timezone.utc)
    events_index = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    
    # 添加时间范围
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)
    
    from app.core.time import to_rfc3339
    dsl_query['bool']['must'].append({
        "range": {
            "@timestamp": {
                "gte": to_rfc3339(start_time),
                "lte": to_rfc3339(end_time)
            }
        }
    })
    
    refresh_index(events_index)
    
    try:
        resp = client.search(
            index=events_index,
            body={
                "query": dsl_query,
                "size": 10
            }
        )
        
        total = resp.get('hits', {}).get('total', {})
        count = total.get('value', 0) if isinstance(total, dict) else total
        
        print(f"\n匹配结果: {count} 个事件")
        
        if count > 0:
            print("\n匹配的事件示例:")
            hits = resp.get('hits', {}).get('hits', [])
            for i, hit in enumerate(hits[:5], 1):
                event = hit.get('_source', {})
                host_name = event.get('host', {}).get('name', 'N/A')
                src_ip = event.get('source', {}).get('ip', 'N/A')
                dst_ip = event.get('destination', {}).get('ip', 'N/A')
                dst_port = event.get('destination', {}).get('port', 'N/A')
                direction = event.get('network', {}).get('direction', 'N/A')
                
                print(f"\n  事件 {i}:")
                print(f"    host.name: {host_name}")
                print(f"    source.ip: {src_ip}")
                print(f"    destination.ip: {dst_ip}")
                print(f"    destination.port: {dst_port}")
                print(f"    network.direction: {direction}")
                
                # 检查端口是否在排除列表中
                if dst_port in [80, 443, 8080, 8443]:
                    print(f"    [ERROR] 端口 {dst_port} 应该在排除列表中！")
                else:
                    print(f"    [OK] 端口 {dst_port} 不在排除列表中")
        else:
            print("\n[WARNING] 没有匹配到任何事件")
            print("\n可能原因:")
            print("  1. 事件时间不在查询范围内")
            print("  2. 事件缺少必需字段")
            print("  3. 端口都在排除列表中")
            print("  4. 字段格式不匹配")
    
    except Exception as e:
        print(f"[ERROR] 查询失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_not_ports_parsing()
