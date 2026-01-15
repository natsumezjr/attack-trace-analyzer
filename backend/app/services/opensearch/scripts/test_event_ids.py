#!/usr/bin/env python3
"""
测试脚本：验证 canonical findings 中的 event_ids 是否可以查询到原始事件

功能：
1. 从 canonical-findings 索引读取一个 finding
2. 提取 event_ids
3. 尝试使用这些 UUID 查询原始事件
"""

import sys
from pathlib import Path
from datetime import datetime

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS


def test_query_event_by_uuid():
    """测试通过 UUID 查询事件"""
    client = get_client()
    today = datetime.now()
    
    # 1. 从 canonical-findings 读取一个 finding
    canonical_index = get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], today)
    
    print("=" * 80)
    print("测试：验证 event_ids 是否可以查询到原始事件")
    print("=" * 80)
    
    try:
        # 查询一个 canonical finding
        response = client.search(
            index=canonical_index,
            body={
                "size": 1,
                "query": {
                    "exists": {"field": "custom.evidence.event_ids"}
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        
        if not hits:
            print("\n[WARNING] 未找到包含 event_ids 的 canonical finding")
            return
        
        finding = hits[0].get('_source', {})
        finding_id = hits[0].get('_id')
        event_ids = finding.get('custom', {}).get('evidence', {}).get('event_ids', [])
        
        print(f"\n找到 Canonical Finding:")
        print(f"  Finding ID: {finding_id}")
        print(f"  Event IDs 数量: {len(event_ids)}")
        print(f"  前5个 Event IDs:")
        for i, eid in enumerate(event_ids[:5], 1):
            print(f"    {i}. {eid}")
        
        if not event_ids:
            print("\n[WARNING] 该 finding 没有 event_ids")
            return
        
        # 2. 尝试使用第一个 UUID 查询原始事件
        test_uuid = event_ids[0]
        print(f"\n尝试查询第一个 Event ID: {test_uuid}")
        print("-" * 80)
        
        # 方法1: 直接通过 _id 查询
        print("\n方法1: 通过文档 _id 查询")
        events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
        
        try:
            # 尝试查询所有可能的日期索引
            for days_back in range(7):
                check_date = datetime(today.year, today.month, today.day) - timedelta(days=days_back)
                events_index = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], check_date)
                
                try:
                    doc = client.get(index=events_index, id=test_uuid)
                    print(f"  ✓ 在索引 {events_index} 中找到文档")
                    print(f"    文档内容:")
                    source = doc.get('_source', {})
                    event_id = source.get('event', {}).get('id', 'N/A')
                    print(f"      event.id: {event_id}")
                    print(f"      @timestamp: {source.get('@timestamp', 'N/A')}")
                    print(f"      message: {source.get('message', 'N/A')[:100]}...")
                    return
                except Exception as e:
                    if 'not_found' not in str(e).lower():
                        print(f"  ✗ 查询索引 {events_index} 失败: {e}")
                    continue
            
            print(f"  ✗ 在所有日期索引中都未找到文档")
            
        except Exception as e:
            print(f"  ✗ 查询失败: {e}")
        
        # 方法2: 通过 ids 查询
        print("\n方法2: 通过 ids 查询")
        try:
            response = client.search(
                index=events_index_pattern,
                body={
                    "query": {
                        "ids": {
                            "values": [test_uuid]
                        }
                    },
                    "size": 1
                }
            )
            
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                print(f"  ✓ 找到文档")
                source = hits[0].get('_source', {})
                event_id = source.get('event', {}).get('id', 'N/A')
                print(f"     文档 _id: {hits[0].get('_id')}")
                print(f"     event.id: {event_id}")
                print(f"     @timestamp: {source.get('@timestamp', 'N/A')}")
            else:
                print(f"  ✗ 未找到文档")
        except Exception as e:
            print(f"  ✗ 查询失败: {e}")
        
        # 方法3: 通过 event.id 字段查询
        print("\n方法3: 通过 event.id 字段查询")
        try:
            response = client.search(
                index=events_index_pattern,
                body={
                    "query": {
                        "term": {
                            "event.id": test_uuid
                        }
                    },
                    "size": 1
                }
            )
            
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                print(f"  ✓ 找到文档（通过 event.id 字段）")
                source = hits[0].get('_source', {})
                print(f"     文档 _id: {hits[0].get('_id')}")
                print(f"     event.id: {source.get('event', {}).get('id', 'N/A')}")
            else:
                print(f"  ✗ 未找到文档")
        except Exception as e:
            print(f"  ✗ 查询失败: {e}")
        
    except Exception as e:
        print(f"\n[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    from datetime import timedelta
    test_query_event_by_uuid()
