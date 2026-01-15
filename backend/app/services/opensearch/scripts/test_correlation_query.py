#!/usr/bin/env python3
"""
测试correlation查询，检查为什么匹配不到events
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.core.time import to_rfc3339


def test_lateral_movement_query():
    """测试横向移动查询"""
    client = get_client()
    today = datetime.now(timezone.utc)
    idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    
    # 查询最近1小时的数据
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)
    
    print("=" * 80)
    print("测试横向移动 Correlation Query")
    print("=" * 80)
    print(f"\n索引: {idx}")
    print(f"时间范围: {start_time.isoformat()} 到 {end_time.isoformat()}")
    
    # Query1: 提权行为
    query1_string = (
        "event.category.keyword:process AND "
        "event.action:process_start AND "
        "(process.command_line:*sudo* OR process.command_line:*su *) AND "
        "_exists_:host.name"
    )
    
    print(f"\n[Query1] 查询条件: {query1_string}")
    dsl_query1 = {
        "bool": {
            "must": [
                {
                    "query_string": {
                        "query": query1_string,
                        "default_operator": "AND",
                        "analyze_wildcard": True,
                        "lenient": True
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": to_rfc3339(start_time),
                            "lte": to_rfc3339(end_time)
                        }
                    }
                }
            ]
        }
    }
    
    try:
        resp1 = client.search(index=idx, body={"query": dsl_query1, "size": 5})
        total1 = resp1.get('hits', {}).get('total', {})
        if isinstance(total1, dict):
            count1 = total1.get('value', 0)
        else:
            count1 = total1
        hits1 = resp1.get('hits', {}).get('hits', [])
        
        print(f"  匹配到 {count1} 个events")
        if hits1:
            print(f"  示例events:")
            for hit in hits1[:3]:
                source = hit.get('_source', {})
                print(f"    - process.name={source.get('process', {}).get('name')}, "
                      f"command_line={source.get('process', {}).get('command_line', '')[:40]}...")
    except Exception as e:
        print(f"  [ERROR] Query1 失败: {e}")
    
    # Query2: 网络连接
    query2_string = (
        "event.category.keyword:network AND "
        "_exists_:source.ip AND "
        "_exists_:destination.ip AND "
        "_exists_:host.name AND "
        "network.direction:outbound AND "
        "NOT (destination.port:80 OR destination.port:443 OR destination.port:8080 OR destination.port:8443)"
    )
    
    print(f"\n[Query2] 查询条件: {query2_string}")
    dsl_query2 = {
        "bool": {
            "must": [
                {
                    "query_string": {
                        "query": query2_string,
                        "default_operator": "AND",
                        "analyze_wildcard": True,
                        "lenient": True
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": to_rfc3339(start_time),
                            "lte": to_rfc3339(end_time)
                        }
                    }
                }
            ]
        }
    }
    
    try:
        resp2 = client.search(index=idx, body={"query": dsl_query2, "size": 5})
        total2 = resp2.get('hits', {}).get('total', {})
        if isinstance(total2, dict):
            count2 = total2.get('value', 0)
        else:
            count2 = total2
        hits2 = resp2.get('hits', {}).get('hits', [])
        
        print(f"  匹配到 {count2} 个events")
        if hits2:
            print(f"  示例events:")
            for hit in hits2[:3]:
                source = hit.get('_source', {})
                print(f"    - destination.port={source.get('destination', {}).get('port')}, "
                      f"destination.ip={source.get('destination', {}).get('ip')}")
    except Exception as e:
        print(f"  [ERROR] Query2 失败: {e}")
    
    # Query3: 主机B上的提权或认证
    query3_string = (
        "((event.category.keyword:process AND event.action:process_start AND "
        "(process.command_line:*sudo* OR process.command_line:*su *)) OR "
        "(event.category.keyword:authentication AND event.action:user_login)) AND "
        "_exists_:host.name"
    )
    
    print(f"\n[Query3] 查询条件: {query3_string}")
    dsl_query3 = {
        "bool": {
            "must": [
                {
                    "query_string": {
                        "query": query3_string,
                        "default_operator": "AND",
                        "analyze_wildcard": True,
                        "lenient": True
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": to_rfc3339(start_time),
                            "lte": to_rfc3339(end_time)
                        }
                    }
                }
            ]
        }
    }
    
    try:
        resp3 = client.search(index=idx, body={"query": dsl_query3, "size": 5})
        total3 = resp3.get('hits', {}).get('total', {})
        if isinstance(total3, dict):
            count3 = total3.get('value', 0)
        else:
            count3 = total3
        hits3 = resp3.get('hits', {}).get('hits', [])
        
        print(f"  匹配到 {count3} 个events")
        if hits3:
            print(f"  示例events:")
            for hit in hits3[:3]:
                source = hit.get('_source', {})
                event_cat = source.get('event', {}).get('category', [])
                print(f"    - event.category={event_cat}, "
                      f"event.action={source.get('event', {}).get('action')}")
    except Exception as e:
        print(f"  [ERROR] Query3 失败: {e}")
    
    print(f"\n总结:")
    print(f"  Query1 (提权): {count1} 个events")
    print(f"  Query2 (网络): {count2} 个events")
    print(f"  Query3 (提权/认证): {count3} 个events")
    print(f"\n如果所有查询都返回0，可能是:")
    print(f"  1. 时间范围不匹配（events不在查询时间范围内）")
    print(f"  2. 字段值不匹配（如event.action的值）")
    print(f"  3. 数组字段匹配问题（event.category是数组）")


if __name__ == "__main__":
    test_lateral_movement_query()
