#!/usr/bin/env python3
"""
检查实际生成的events的字段结构，用于调试correlation规则匹配问题
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS


def check_event_fields():
    """检查events的字段结构"""
    client = get_client()
    today = datetime.now(timezone.utc)
    idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    
    print("=" * 80)
    print("检查 Events 字段结构")
    print("=" * 80)
    print(f"\n索引: {idx}")
    
    try:
        # 获取最近的几个events
        resp = client.search(index=idx, body={
            "query": {"match_all": {}},
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}]
        })
        
        hits = resp.get('hits', {}).get('hits', [])
        total = resp.get('hits', {}).get('total', {})
        if isinstance(total, dict):
            total_count = total.get('value', 0)
        else:
            total_count = total
        
        print(f"\n总events数: {total_count}")
        print(f"检查最近 {len(hits)} 个events的字段结构:\n")
        
        for i, hit in enumerate(hits, 1):
            source = hit.get('_source', {})
            print(f"[Event {i}]")
            print(f"  ID: {hit.get('_id')}")
            print(f"  @timestamp: {source.get('@timestamp')}")
            
            # 检查event字段
            event = source.get('event', {})
            print(f"  event.category: {event.get('category')} (类型: {type(event.get('category'))})")
            print(f"  event.action: {event.get('action')} (类型: {type(event.get('action'))})")
            print(f"  event.type: {event.get('type')} (类型: {type(event.get('type'))})")
            
            # 检查host字段
            host = source.get('host', {})
            print(f"  host.name: {host.get('name')} (存在: {bool(host.get('name'))})")
            print(f"  host.id: {host.get('id')}")
            
            # 检查process字段
            process = source.get('process', {})
            if process:
                print(f"  process.name: {process.get('name')}")
                print(f"  process.command_line: {process.get('command_line', '')[:50]}...")
                parent = process.get('parent', {})
                if parent:
                    print(f"  process.parent.name: {parent.get('name')}")
            
            # 检查network字段
            network = source.get('network', {})
            if network:
                print(f"  network.direction: {network.get('direction')}")
            
            # 检查source/destination
            source_field = source.get('source', {})
            dest_field = source.get('destination', {})
            if source_field:
                print(f"  source.ip: {source_field.get('ip')}")
            if dest_field:
                print(f"  destination.ip: {dest_field.get('ip')}")
                print(f"  destination.port: {dest_field.get('port')}")
            
            print()
        
        # 测试查询条件
        print("\n" + "=" * 80)
        print("测试查询条件")
        print("=" * 80)
        
        # Query1测试 - 使用query_string（模拟correlation规则）
        print("\n[Query1] 测试横向移动Query1条件（使用query_string，模拟correlation规则）:")
        query1_string = (
            "event.category.keyword:process AND "
            "event.action:process_start AND "
            "(process.command_line:*sudo* OR process.command_line:*su *) AND "
            "_exists_:host.name"
        )
        query1 = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": query1_string,
                                "default_operator": "AND",
                                "analyze_wildcard": True,
                                "lenient": True
                            }
                        }
                    ]
                }
            },
            "size": 5
        }
        resp1 = client.search(index=idx, body=query1)
        hits1 = resp1.get('hits', {}).get('hits', [])
        total1 = resp1.get('hits', {}).get('total', {})
        if isinstance(total1, dict):
            count1 = total1.get('value', 0)
        else:
            count1 = total1
        print(f"  匹配到 {count1} 个events")
        if hits1:
            print(f"  示例: process.name={hits1[0].get('_source', {}).get('process', {}).get('name')}")
        
        # Query2测试 - 使用query_string（模拟correlation规则）
        print("\n[Query2] 测试横向移动Query2条件（使用query_string，模拟correlation规则）:")
        query2_string = (
            "event.category.keyword:network AND "
            "_exists_:source.ip AND "
            "_exists_:destination.ip AND "
            "_exists_:host.name AND "
            "network.direction:outbound AND "
            "NOT (destination.port:80 OR destination.port:443 OR destination.port:8080 OR destination.port:8443)"
        )
        query2 = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": query2_string,
                                "default_operator": "AND",
                                "analyze_wildcard": True,
                                "lenient": True
                            }
                        }
                    ]
                }
            },
            "size": 5
        }
        resp2 = client.search(index=idx, body=query2)
        hits2 = resp2.get('hits', {}).get('hits', [])
        total2 = resp2.get('hits', {}).get('total', {})
        if isinstance(total2, dict):
            count2 = total2.get('value', 0)
        else:
            count2 = total2
        print(f"  匹配到 {count2} 个events")
        if hits2:
            print(f"  示例: destination.port={hits2[0].get('_source', {}).get('destination', {}).get('port')}")
        
        # 检查event.category的值
        print("\n[统计] event.category 分布:")
        resp3 = client.search(index=idx, body={
            "size": 0,
            "aggs": {
                "categories": {
                    "terms": {"field": "event.category.keyword", "size": 10}
                }
            }
        })
        buckets = resp3.get('aggregations', {}).get('categories', {}).get('buckets', [])
        for b in buckets:
            print(f"  {b['key']}: {b['doc_count']} 个")
        
        # 检查event.action的值
        print("\n[统计] event.action 分布:")
        resp4 = client.search(index=idx, body={
            "size": 0,
            "aggs": {
                "actions": {
                    "terms": {"field": "event.action.keyword", "size": 10}
                }
            }
        })
        buckets = resp4.get('aggregations', {}).get('actions', {}).get('buckets', [])
        for b in buckets:
            print(f"  {b['key']}: {b['doc_count']} 个")
        
    except Exception as e:
        print(f"[ERROR] 查询失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    check_event_fields()
