#!/usr/bin/env python3
"""
优化批量写入，避免OOM

功能：
1. 分批写入events（每批200-500个）
2. 减少refresh频率（只在最后refresh一次）
3. 临时调整refresh_interval
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.storage import store_events
from app.services.opensearch.internal import get_client
from app.services.opensearch.index import initialize_indices


def store_events_optimized(events: list, batch_size: int = 300, refresh_after: bool = True):
    """
    优化的批量写入（分批写入，减少内存压力）
    
    参数：
    - events: 要写入的events列表
    - batch_size: 每批写入的数量（默认300）
    - refresh_after: 是否在最后refresh（默认True）
    """
    client = get_client()
    
    print("=" * 80)
    print("优化的批量写入")
    print("=" * 80)
    print(f"\n总events数: {len(events)}")
    print(f"每批大小: {batch_size}")
    print(f"总批数: {(len(events) + batch_size - 1) // batch_size}")
    
    # 临时调整refresh_interval为30秒（减少refresh频率）
    try:
        # 获取所有可能用到的索引
        from app.services.opensearch.index import INDEX_PATTERNS, get_index_name
        today = datetime.now(timezone.utc)
        indices_to_optimize = [
            get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
        ]
        
        print("\n[1] 临时调整refresh_interval为30秒...")
        for idx in indices_to_optimize:
            try:
                client.indices.put_settings(
                    index=idx,
                    body={
                        "index": {
                            "refresh_interval": "30s"
                        }
                    }
                )
                print(f"  [OK] {idx}: refresh_interval设置为30秒")
            except Exception as e:
                print(f"  [WARNING] {idx}: 设置失败（可能索引不存在）: {e}")
    except Exception as e:
        print(f"  [WARNING] 调整refresh_interval失败: {e}")
    
    # 分批写入
    print("\n[2] 分批写入events...")
    total_success = 0
    total_failed = 0
    
    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (len(events) + batch_size - 1) // batch_size
        
        print(f"\n  批次 {batch_num}/{total_batches}: {len(batch)} 个events")
        
        try:
            # 使用store_events，但不refresh（已优化）
            result = store_events(batch)
            
            batch_success = result.get('success', 0)
            batch_failed = result.get('failed', 0)
            
            total_success += batch_success
            total_failed += batch_failed
            
            print(f"    成功: {batch_success}, 失败: {batch_failed}")
            
            # 每批之间稍作延迟，避免压力过大
            if i + batch_size < len(events):
                import time
                time.sleep(0.5)  # 延迟0.5秒
                
        except Exception as e:
            print(f"    [ERROR] 批次 {batch_num} 写入失败: {e}")
            total_failed += len(batch)
            import traceback
            traceback.print_exc()
    
    # 最后refresh一次
    if refresh_after and total_success > 0:
        print("\n[3] 最后refresh一次索引...")
        try:
            from app.services.opensearch.index import INDEX_PATTERNS, get_index_name
            today = datetime.now(timezone.utc)
            idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
            from app.services.opensearch.client import refresh_index
            refresh_index(idx)
            print(f"  [OK] {idx} refresh完成")
        except Exception as e:
            print(f"  [WARNING] refresh失败: {e}")
    
    # 恢复refresh_interval
    try:
        print("\n[4] 恢复refresh_interval为1秒...")
        for idx in indices_to_optimize:
            try:
                client.indices.put_settings(
                    index=idx,
                    body={
                        "index": {
                            "refresh_interval": "1s"
                        }
                    }
                )
                print(f"  [OK] {idx}: refresh_interval恢复为1秒")
            except Exception as e:
                pass
    except Exception as e:
        print(f"  [WARNING] 恢复refresh_interval失败: {e}")
    
    print("\n" + "=" * 80)
    print("完成")
    print("=" * 80)
    print(f"  成功: {total_success}")
    print(f"  失败: {total_failed}")
    print(f"  总计: {len(events)}")
    
    return {
        "success": total_success,
        "failed": total_failed,
        "total": len(events)
    }


if __name__ == "__main__":
    print("这是一个优化批量写入的工具函数")
    print("使用方法：")
    print("  from app.services.opensearch.scripts.optimize_bulk_write import store_events_optimized")
    print("  store_events_optimized(events, batch_size=300)")
