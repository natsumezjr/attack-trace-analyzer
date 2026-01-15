#!/usr/bin/env python3
"""
查看 OpenSearch Security Analytics 规则统计信息
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client

SA_RULES_SEARCH_API = "/_plugins/_security_analytics/rules/_search"


def check_rules_stats():
    """查看规则统计信息"""
    client = get_client()
    
    try:
        # 查询所有规则并聚合统计
        resp = client.transport.perform_request(
            'POST',
            SA_RULES_SEARCH_API,
            body={
                "query": {"match_all": {}},
                "size": 0,
                "aggs": {
                    "by_category": {
                        "terms": {"field": "category.keyword", "size": 20}
                    },
                    "by_index": {
                        "terms": {"field": "_index", "size": 10}
                    }
                }
            }
        )
        
        total = resp.get('hits', {}).get('total', {}).get('value', 0)
        print("=" * 80)
        print(f"规则总数: {total}")
        print("=" * 80)
        
        # 按category统计
        print("\n按 Category 统计:")
        print("-" * 80)
        by_category = resp.get('aggregations', {}).get('by_category', {}).get('buckets', [])
        for bucket in by_category:
            print(f"  {bucket['key']}: {bucket['doc_count']} 个")
        
        # 按索引统计（区分预打包和自定义）
        print("\n按索引统计（区分预打包和自定义规则）:")
        print("-" * 80)
        by_index = resp.get('aggregations', {}).get('by_index', {}).get('buckets', [])
        prepackaged_count = 0
        custom_count = 0
        
        for bucket in by_index:
            index_name = bucket['key']
            count = bucket['doc_count']
            
            if 'pre-packaged' in index_name.lower() or 'prepackaged' in index_name.lower():
                prepackaged_count += count
                print(f"  {index_name}: {count} 个 (预打包)")
            else:
                custom_count += count
                print(f"  {index_name}: {count} 个 (自定义)")
        
        print("\n" + "-" * 80)
        print(f"预打包规则总计: {prepackaged_count} 个")
        print(f"自定义规则总计: {custom_count} 个")
        print(f"总计: {total} 个")
        
    except Exception as e:
        print(f"[ERROR] 查询规则统计失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    check_rules_stats()
