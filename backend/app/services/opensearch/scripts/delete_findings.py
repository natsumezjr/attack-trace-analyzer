#!/usr/bin/env python3
"""
删除所有 Findings 索引

功能：
1. 删除所有 Raw Findings 索引
2. 删除所有 Canonical Findings 索引
3. 可选：删除特定日期的索引
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from opensearch import get_client, get_index_name, INDEX_PATTERNS


def delete_all_findings():
    """删除所有findings索引"""
    client = get_client()
    
    print("=" * 80)
    print("删除所有 Findings 索引")
    print("=" * 80)
    
    deleted_count = 0
    
    # 1. 删除Raw Findings索引
    print("\n[1] 删除 Raw Findings 索引...")
    raw_pattern = INDEX_PATTERNS['RAW_FINDINGS']
    
    # 获取所有匹配的索引
    try:
        indices = client.indices.get_alias(index=f"{raw_pattern.replace('*', '')}*")
        raw_indices = list(indices.keys())
        
        if raw_indices:
            print(f"  找到 {len(raw_indices)} 个Raw Findings索引:")
            for idx in raw_indices:
                print(f"    - {idx}")
            
            # 删除索引
            for idx in raw_indices:
                try:
                    client.indices.delete(index=idx)
                    print(f"  [OK] 已删除: {idx}")
                    deleted_count += 1
                except Exception as e:
                    print(f"  [ERROR] 删除失败 {idx}: {e}")
        else:
            print("  [INFO] 没有找到Raw Findings索引")
    except Exception as e:
        print(f"  [WARNING] 查询Raw Findings索引失败: {e}")
    
    # 2. 删除Canonical Findings索引
    print("\n[2] 删除 Canonical Findings 索引...")
    canonical_pattern = INDEX_PATTERNS['CANONICAL_FINDINGS']
    
    try:
        indices = client.indices.get_alias(index=f"{canonical_pattern.replace('*', '')}*")
        canonical_indices = list(indices.keys())
        
        if canonical_indices:
            print(f"  找到 {len(canonical_indices)} 个Canonical Findings索引:")
            for idx in canonical_indices:
                print(f"    - {idx}")
            
            # 删除索引
            for idx in canonical_indices:
                try:
                    client.indices.delete(index=idx)
                    print(f"  [OK] 已删除: {idx}")
                    deleted_count += 1
                except Exception as e:
                    print(f"  [ERROR] 删除失败 {idx}: {e}")
        else:
            print("  [INFO] 没有找到Canonical Findings索引")
    except Exception as e:
        print(f"  [WARNING] 查询Canonical Findings索引失败: {e}")
    
    # 3. 总结
    print("\n" + "=" * 80)
    print("删除完成")
    print("=" * 80)
    print(f"\n总共删除了 {deleted_count} 个索引")
    
    if deleted_count > 0:
        print("\n现在可以重新运行检测:")
        print("  cd backend/opensearch/scripts")
        print("  uv run python test_detection.py --all")
    
    return deleted_count


def delete_recent_findings(days: int = 7):
    """删除最近N天的findings索引"""
    client = get_client()
    
    print("=" * 80)
    print(f"删除最近 {days} 天的 Findings 索引")
    print("=" * 80)
    
    deleted_count = 0
    today = datetime.now()
    
    # 删除最近N天的索引
    for i in range(days):
        date = today - timedelta(days=i)
        
        # Raw Findings
        raw_index = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], date)
        if client.indices.exists(index=raw_index):
            try:
                client.indices.delete(index=raw_index)
                print(f"[OK] 已删除: {raw_index}")
                deleted_count += 1
            except Exception as e:
                print(f"[ERROR] 删除失败 {raw_index}: {e}")
        
        # Canonical Findings
        canonical_index = get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], date)
        if client.indices.exists(index=canonical_index):
            try:
                client.indices.delete(index=canonical_index)
                print(f"[OK] 已删除: {canonical_index}")
                deleted_count += 1
            except Exception as e:
                print(f"[ERROR] 删除失败 {canonical_index}: {e}")
    
    print(f"\n总共删除了 {deleted_count} 个索引")
    return deleted_count


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="删除Findings索引")
    parser.add_argument(
        "--days",
        type=int,
        help="只删除最近N天的索引（默认：删除所有）"
    )
    args = parser.parse_args()
    
    if args.days:
        delete_recent_findings(args.days)
    else:
        delete_all_findings()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
