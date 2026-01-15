#!/usr/bin/env python3
"""
列出所有OpenSearch索引

功能：
1. 列出所有索引
2. 按类型分组显示（Events, Raw Findings, Canonical Findings等）
3. 显示每个索引的文档数量
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS, initialize_indices
from app.services.opensearch.client import index_exists


def list_all_indices():
    """列出所有索引，如果缺少必要索引则自动创建"""
    client = get_client()
    
    print("=" * 80)
    print("OpenSearch 索引列表")
    print("=" * 80)
    
    # 检查并创建缺失的必要索引
    today = datetime.now(timezone.utc)
    required_indices = {
        "ECS_EVENTS": get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today),
        "RAW_FINDINGS": get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today),
        "CANONICAL_FINDINGS": get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today),
    }
    
    missing_indices = []
    for index_type, index_name in required_indices.items():
        if not index_exists(index_name):
            missing_indices.append((index_type, index_name))
    
    if missing_indices:
        print(f"\n[INFO] 检测到 {len(missing_indices)} 个缺失的必要索引，正在自动创建...")
        for index_type, index_name in missing_indices:
            print(f"  - {index_type}: {index_name}")
        
        try:
            initialize_indices()
            print("[OK] 索引创建完成")
        except Exception as e:
            print(f"[WARNING] 自动创建索引失败: {e}")
            print("[INFO] 将继续列出现有索引")
    
    try:
        # 获取所有索引
        indices = client.indices.get_alias(index="*")
        all_indices = list(indices.keys())
        
        if not all_indices:
            print("\n[INFO] 没有找到任何索引")
            return
        
        # 按类型分组
        events_indices = []
        raw_findings_indices = []
        canonical_findings_indices = []
        other_indices = []
        
        for idx in sorted(all_indices):
            # 跳过系统索引（以.开头的）
            if idx.startswith('.'):
                continue
            
            if 'events' in idx.lower() or idx.startswith('ecs-events'):
                events_indices.append(idx)
            elif 'raw-findings' in idx.lower() or idx.startswith('raw-findings'):
                raw_findings_indices.append(idx)
            elif 'canonical-findings' in idx.lower() or idx.startswith('canonical-findings'):
                canonical_findings_indices.append(idx)
            else:
                other_indices.append(idx)
        
        # 显示Events索引
        if events_indices:
            print("\n[Events 索引]")
            print("-" * 80)
            for idx in events_indices:
                try:
                    stats = client.count(index=idx)
                    count = stats.get('count', 0)
                    print(f"  {idx:50s} - {count:>10,} 个文档")
                except Exception as e:
                    print(f"  {idx:50s} - [ERROR] {e}")
        
        # 显示Raw Findings索引
        if raw_findings_indices:
            print("\n[Raw Findings 索引]")
            print("-" * 80)
            for idx in raw_findings_indices:
                try:
                    stats = client.count(index=idx)
                    count = stats.get('count', 0)
                    print(f"  {idx:50s} - {count:>10,} 个文档")
                except Exception as e:
                    print(f"  {idx:50s} - [ERROR] {e}")
        
        # 显示Canonical Findings索引
        if canonical_findings_indices:
            print("\n[Canonical Findings 索引]")
            print("-" * 80)
            for idx in canonical_findings_indices:
                try:
                    stats = client.count(index=idx)
                    count = stats.get('count', 0)
                    print(f"  {idx:50s} - {count:>10,} 个文档")
                except Exception as e:
                    print(f"  {idx:50s} - [ERROR] {e}")
        
        # 显示其他索引
        if other_indices:
            print("\n[其他索引]")
            print("-" * 80)
            for idx in other_indices:
                try:
                    stats = client.count(index=idx)
                    count = stats.get('count', 0)
                    print(f"  {idx:50s} - {count:>10,} 个文档")
                except Exception as e:
                    print(f"  {idx:50s} - [ERROR] {e}")
        
        # 统计信息
        print("\n" + "=" * 80)
        print("统计信息")
        print("=" * 80)
        
        total_indices = len(events_indices) + len(raw_findings_indices) + len(canonical_findings_indices) + len(other_indices)
        print(f"\n总索引数: {total_indices}")
        print(f"  - Events: {len(events_indices)}")
        print(f"  - Raw Findings: {len(raw_findings_indices)}")
        print(f"  - Canonical Findings: {len(canonical_findings_indices)}")
        print(f"  - 其他: {len(other_indices)}")
        
        # 计算总文档数
        total_docs = 0
        for idx_list in [events_indices, raw_findings_indices, canonical_findings_indices, other_indices]:
            for idx in idx_list:
                try:
                    stats = client.count(index=idx)
                    total_docs += stats.get('count', 0)
                except:
                    pass
        
        print(f"\n总文档数: {total_docs:,}")
        
    except Exception as e:
        print(f"\n[ERROR] 获取索引列表失败: {e}")
        import traceback
        traceback.print_exc()


def list_indices_by_pattern(pattern: str):
    """按模式列出索引"""
    client = get_client()
    
    print(f"\n查找匹配模式 '{pattern}' 的索引...")
    
    try:
        indices = client.indices.get_alias(index=f"*{pattern}*")
        matching_indices = list(indices.keys())
        
        if matching_indices:
            print(f"\n找到 {len(matching_indices)} 个匹配的索引:")
            for idx in sorted(matching_indices):
                try:
                    stats = client.count(index=idx)
                    count = stats.get('count', 0)
                    print(f"  {idx:50s} - {count:>10,} 个文档")
                except Exception as e:
                    print(f"  {idx:50s} - [ERROR] {e}")
        else:
            print(f"\n[INFO] 没有找到匹配模式 '{pattern}' 的索引")
    except Exception as e:
        print(f"\n[ERROR] 查询失败: {e}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="列出OpenSearch索引")
    parser.add_argument(
        "--pattern",
        type=str,
        help="按模式过滤索引（如：events, findings等）"
    )
    args = parser.parse_args()
    
    if args.pattern:
        list_indices_by_pattern(args.pattern)
    else:
        list_all_indices()
    
    print("\n" + "=" * 80)
    print("完成")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
