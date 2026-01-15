#!/usr/bin/env python3
"""
工具脚本：通过 UUID 查询事件的文档 _id

功能：
1. 通过 UUID（可能是 event.id 或其他字段）查询文档
2. 返回文档的 _id 和 event.id
3. 支持批量查询

使用方法:
    # 查询单个 UUID
    uv run python get_document_id.py --uuid 09af752d-b5a1-4805-9ee6-97d941064239
    
    # 批量查询
    uv run python get_document_id.py --uuids 09af752d-b5a1-4805-9ee6-97d941064239,1d8d0232-e7e4-44e6-90ef-53157c1eeaa1
    
    # 从 canonical finding 中提取 UUID 并查询
    uv run python get_document_id.py --from-canonical
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.services.opensearch.analysis import get_document_id_by_uuid, get_document_ids_by_uuids


def query_document_by_uuid(uuid: str):
    """查询单个 UUID 对应的文档"""
    client = get_client()
    index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    print(f"查询 UUID: {uuid}")
    print("=" * 80)
    
    # 方法1: 尝试直接通过 _id 查询
    today = datetime.now()
    found = False
    
    for days_back in range(7):
        check_date = datetime(today.year, today.month, today.day) - timedelta(days=days_back)
        index_name = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], check_date)
        
        try:
            doc = client.get(index=index_name, id=uuid)
            print(f"\n✓ 在索引 {index_name} 中找到文档")
            print(f"  文档 _id: {doc.get('_id')}")
            source = doc.get('_source', {})
            event_id = source.get('event', {}).get('id', 'N/A')
            print(f"  event.id: {event_id}")
            print(f"  @timestamp: {source.get('@timestamp', 'N/A')}")
            print(f"  message: {source.get('message', 'N/A')[:100]}...")
            found = True
            return doc.get('_id'), event_id
        except Exception:
            continue
    
    if not found:
        # 方法2: 通过 event.id 字段查询
        print("\n尝试通过 event.id 字段查询...")
        try:
            response = client.search(
                index=index_pattern,
                body={
                    "query": {
                        "term": {
                            "event.id": uuid
                        }
                    },
                    "size": 1
                }
            )
            
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                doc_id = hits[0].get('_id')
                source = hits[0].get('_source', {})
                event_id = source.get('event', {}).get('id', 'N/A')
                
                print(f"\n✓ 找到文档")
                print(f"  文档 _id: {doc_id}")
                print(f"  event.id: {event_id}")
                print(f"  @timestamp: {source.get('@timestamp', 'N/A')}")
                return doc_id, event_id
        except Exception as e:
            print(f"  ✗ 查询失败: {e}")
        
        # 方法3: 通过 ids 查询
        print("\n尝试通过 ids 查询...")
        try:
            response = client.search(
                index=index_pattern,
                body={
                    "query": {
                        "ids": {
                            "values": [uuid]
                        }
                    },
                    "size": 1
                }
            )
            
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                doc_id = hits[0].get('_id')
                source = hits[0].get('_source', {})
                event_id = source.get('event', {}).get('id', 'N/A')
                
                print(f"\n✓ 找到文档")
                print(f"  文档 _id: {doc_id}")
                print(f"  event.id: {event_id}")
                return doc_id, event_id
        except Exception as e:
            print(f"  ✗ 查询失败: {e}")
        
        print(f"\n✗ 未找到文档")
        return None, None


def query_from_canonical():
    """从 canonical findings 中提取 UUID 并查询"""
    client = get_client()
    today = datetime.now()
    canonical_index = get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], today)
    
    print("从 Canonical Findings 中提取 event_ids 并查询文档 ID")
    print("=" * 80)
    
    try:
        # 查询一个包含 event_ids 的 canonical finding
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
        event_ids = finding.get('custom', {}).get('evidence', {}).get('event_ids', [])
        
        print(f"\n找到 Canonical Finding:")
        print(f"  Finding ID: {hits[0].get('_id')}")
        print(f"  Event IDs 数量: {len(event_ids)}")
        
        if not event_ids:
            print("\n[WARNING] 该 finding 没有 event_ids")
            return
        
        # 查询前5个 UUID
        print(f"\n查询前 {min(5, len(event_ids))} 个 UUID:")
        print("-" * 80)
        
        results = []
        for i, uuid in enumerate(event_ids[:5], 1):
            print(f"\n[{i}] UUID: {uuid}")
            doc_id, event_id = query_document_by_uuid(uuid)
            results.append({
                "uuid": uuid,
                "document_id": doc_id,
                "event_id": event_id
            })
        
        # 汇总
        print("\n" + "=" * 80)
        print("查询结果汇总")
        print("=" * 80)
        print(f"\n{'UUID':<40} {'文档 _id':<40} {'event.id':<40}")
        print("-" * 120)
        for r in results:
            doc_id = r['document_id'] or '未找到'
            event_id = r['event_id'] or 'N/A'
            print(f"{r['uuid']:<40} {doc_id:<40} {event_id:<40}")
        
    except Exception as e:
        print(f"\n[ERROR] 查询失败: {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="通过 UUID 查询事件的文档 _id")
    parser.add_argument("--uuid", type=str, help="单个 UUID 查询")
    parser.add_argument("--uuids", type=str, help="多个 UUID（逗号分隔）")
    parser.add_argument("--from-canonical", action="store_true", help="从 canonical findings 中提取 UUID 并查询")
    
    args = parser.parse_args()
    
    if args.from_canonical:
        query_from_canonical()
    elif args.uuid:
        query_document_by_uuid(args.uuid)
    elif args.uuids:
        uuids = [u.strip() for u in args.uuids.split(',')]
        print(f"批量查询 {len(uuids)} 个 UUID")
        print("=" * 80)
        
        for i, uuid in enumerate(uuids, 1):
            print(f"\n[{i}/{len(uuids)}]")
            query_document_by_uuid(uuid)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
