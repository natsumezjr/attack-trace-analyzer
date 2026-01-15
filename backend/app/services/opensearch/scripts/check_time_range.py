#!/usr/bin/env python3
"""
检查events的时间范围和correlation查询的时间范围是否匹配
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.core.time import to_rfc3339


def check_time_range():
    """检查时间范围"""
    client = get_client()
    today = datetime.now(timezone.utc)
    idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    
    print("=" * 80)
    print("检查时间范围匹配")
    print("=" * 80)
    
    # 1. 检查events的时间范围
    print("\n[1] Events 时间范围:")
    resp = client.search(index=idx, body={
        "size": 0,
        "aggs": {
            "time_range": {
                "stats": {
                    "field": "@timestamp"
                }
            }
        }
    })
    
    stats = resp.get('aggregations', {}).get('time_range', {})
    min_time_ms = stats.get('min', 0)
    max_time_ms = stats.get('max', 0)
    
    if min_time_ms and max_time_ms:
        min_time = datetime.fromtimestamp(min_time_ms / 1000, tz=timezone.utc)
        max_time = datetime.fromtimestamp(max_time_ms / 1000, tz=timezone.utc)
        print(f"  最早event: {min_time.isoformat()}")
        print(f"  最晚event: {max_time.isoformat()}")
        print(f"  时间跨度: {(max_time - min_time).total_seconds() / 60:.1f} 分钟")
    else:
        print("  [WARNING] 无法获取时间范围")
        return
    
    # 2. Correlation查询的时间范围（默认30分钟）
    print("\n[2] Correlation 查询时间范围（默认30分钟窗口）:")
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=30)
    print(f"  查询开始: {start_time.isoformat()}")
    print(f"  查询结束: {end_time.isoformat()}")
    print(f"  时间跨度: 30 分钟")
    
    # 3. 检查是否有重叠
    print("\n[3] 时间范围重叠检查:")
    if max_time < start_time:
        print(f"  [WARNING] Events 最晚时间是 {max_time.isoformat()}")
        print(f"  [WARNING] 但查询开始时间是 {start_time.isoformat()}")
        print(f"  [WARNING] Events 在查询时间范围之前，无法匹配！")
        print(f"\n  建议:")
        print(f"    1. 生成新的events（使用当前时间）")
        print(f"    2. 或者增加查询时间窗口（使用 --time-window-minutes 参数）")
    elif min_time > end_time:
        print(f"  [WARNING] Events 最早时间是 {min_time.isoformat()}")
        print(f"  [WARNING] 但查询结束时间是 {end_time.isoformat()}")
        print(f"  [WARNING] Events 在查询时间范围之后，无法匹配！")
    else:
        overlap_start = max(min_time, start_time)
        overlap_end = min(max_time, end_time)
        overlap_minutes = (overlap_end - overlap_start).total_seconds() / 60
        print(f"  [OK] 有重叠时间范围:")
        print(f"    重叠开始: {overlap_start.isoformat()}")
        print(f"    重叠结束: {overlap_end.isoformat()}")
        print(f"    重叠时长: {overlap_minutes:.1f} 分钟")
    
    # 4. 测试查询（使用实际的时间范围）
    print("\n[4] 测试查询（使用events的实际时间范围）:")
    test_start = min_time - timedelta(minutes=5)  # 稍微提前一点
    test_end = max_time + timedelta(minutes=5)  # 稍微延后一点
    
    query_test = {
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "event.category:process AND event.action:process_start AND process.command_line:*sudo*",
                            "default_operator": "AND",
                            "analyze_wildcard": True,
                            "lenient": True
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_rfc3339(test_start),
                                "lte": to_rfc3339(test_end)
                            }
                        }
                    }
                ]
            }
        },
        "size": 5
    }
    
    try:
        resp_test = client.search(index=idx, body=query_test)
        total_test = resp_test.get('hits', {}).get('total', {})
        if isinstance(total_test, dict):
            count_test = total_test.get('value', 0)
        else:
            count_test = total_test
        
        print(f"  使用events实际时间范围查询，匹配到 {count_test} 个events")
        if count_test > 0:
            print(f"  [OK] 查询可以正常工作，问题是时间范围不匹配")
        else:
            print(f"  [ERROR] 即使使用events的实际时间范围也匹配不到，可能是查询条件问题")
    except Exception as e:
        print(f"  [ERROR] 测试查询失败: {e}")


if __name__ == "__main__":
    check_time_range()
