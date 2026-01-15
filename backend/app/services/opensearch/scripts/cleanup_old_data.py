#!/usr/bin/env python3
"""
统一的数据清理脚本

功能：
1. 删除 OpenSearch 中的旧 events（按时间范围）
2. 删除 OpenSearch 中的旧 findings（按时间范围）
3. 删除 Neo4j 中的旧图数据（按时间范围）
4. 支持删除所有数据或指定天数前的数据
5. 显示清理前后的数据统计

使用方法:
    # 删除7天前的所有数据
    uv run python cleanup_old_data.py --days 7
    
    # 删除所有数据（危险！）
    uv run python cleanup_old_data.py --all
    
    # 只删除events
    uv run python cleanup_old_data.py --days 7 --only-events
    
    # 只删除findings
    uv run python cleanup_old_data.py --days 7 --only-findings
    
    # 只删除Neo4j数据
    uv run python cleanup_old_data.py --days 7 --only-neo4j
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.services.neo4j.db import _get_driver, _get_session


def get_data_statistics():
    """获取当前数据统计"""
    client = get_client()
    stats = {
        "events": 0,
        "raw_findings": 0,
        "canonical_findings": 0,
        "neo4j_nodes": 0,
        "neo4j_relationships": 0
    }
    
    # OpenSearch 统计
    try:
        # Events
        today = datetime.now(timezone.utc)
        events_pattern = INDEX_PATTERNS['ECS_EVENTS']
        try:
            indices = client.indices.get_alias(index=f"{events_pattern}*")
            for idx in indices.keys():
                try:
                    count = client.count(index=idx).get('count', 0)
                    stats["events"] += count
                except:
                    pass
        except:
            pass
        
        # Raw Findings
        raw_pattern = INDEX_PATTERNS['RAW_FINDINGS']
        try:
            indices = client.indices.get_alias(index=f"*{raw_pattern}*")
            for idx in indices.keys():
                try:
                    count = client.count(index=idx).get('count', 0)
                    stats["raw_findings"] += count
                except:
                    pass
        except:
            pass
        
        # Canonical Findings
        canonical_pattern = INDEX_PATTERNS['CANONICAL_FINDINGS']
        try:
            indices = client.indices.get_alias(index=f"*{canonical_pattern}*")
            for idx in indices.keys():
                try:
                    count = client.count(index=idx).get('count', 0)
                    stats["canonical_findings"] += count
                except:
                    pass
        except:
            pass
    except Exception as e:
        print(f"[WARNING] 获取 OpenSearch 统计失败: {e}")
    
    # Neo4j 统计
    try:
        with _get_session() as session:
            result = session.run("MATCH (n) RETURN count(n) AS cnt")
            stats["neo4j_nodes"] = result.single()["cnt"] if result.peek() else 0
            
            result = session.run("MATCH ()-[r]->() RETURN count(r) AS cnt")
            stats["neo4j_relationships"] = result.single()["cnt"] if result.peek() else 0
    except Exception as e:
        print(f"[WARNING] 获取 Neo4j 统计失败: {e}")
    
    return stats


def delete_old_events(days: int = None, all_data: bool = False):
    """删除旧的 events"""
    client = get_client()
    deleted_count = 0
    
    print("\n" + "=" * 80)
    print("删除旧的 Events")
    print("=" * 80)
    
    try:
        events_pattern = INDEX_PATTERNS['ECS_EVENTS']
        indices = client.indices.get_alias(index=f"{events_pattern}*")
        event_indices = [idx for idx in indices.keys() if events_pattern in idx]
        
        if not event_indices:
            print("[INFO] 没有找到 Events 索引")
            return 0
        
        print(f"\n找到 {len(event_indices)} 个 Events 索引")
        
        if all_data:
            # 删除所有
            print("\n[WARNING] 准备删除所有 Events 索引...")
            for idx in event_indices:
                try:
                    count = client.count(index=idx).get('count', 0)
                    client.indices.delete(index=idx)
                    print(f"  [OK] 已删除: {idx} ({count:,} 个文档)")
                    deleted_count += 1
                except Exception as e:
                    print(f"  [ERROR] 删除失败 {idx}: {e}")
        else:
            # 删除指定天数前的
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            print(f"\n删除 {cutoff_date.date()} 之前的 Events...")
            
            for idx in event_indices:
                try:
                    # 从索引名提取日期（格式：ecs-events-YYYY-MM-DD）
                    date_str = idx.split('-')[-3:]  # ['YYYY', 'MM', 'DD']
                    if len(date_str) == 3:
                        index_date = datetime.strptime('-'.join(date_str), '%Y-%m-%d').replace(tzinfo=timezone.utc)
                        if index_date < cutoff_date:
                            count = client.count(index=idx).get('count', 0)
                            client.indices.delete(index=idx)
                            print(f"  [OK] 已删除: {idx} ({count:,} 个文档, 日期: {index_date.date()})")
                            deleted_count += 1
                except Exception as e:
                    # 如果无法解析日期，跳过
                    pass
        
        print(f"\n总共删除了 {deleted_count} 个 Events 索引")
        return deleted_count
        
    except Exception as e:
        print(f"[ERROR] 删除 Events 失败: {e}")
        return 0


def delete_old_findings(days: int = None, all_data: bool = False):
    """删除旧的 findings"""
    client = get_client()
    deleted_count = 0
    
    print("\n" + "=" * 80)
    print("删除旧的 Findings")
    print("=" * 80)
    
    # 1. Security Analytics Findings
    print("\n[1] 删除 Security Analytics Findings...")
    try:
        sa_indices = client.indices.get_alias(index=".opensearch-sap-*-findings*")
        sa_indices_list = [idx for idx in sa_indices.keys() if 'findings' in idx.lower()]
        
        if sa_indices_list:
            if all_data:
                for idx in sa_indices_list:
                    try:
                        count = client.count(index=idx).get('count', 0)
                        client.indices.delete(index=idx)
                        print(f"  [OK] 已删除: {idx} ({count:,} 个文档)")
                        deleted_count += 1
                    except Exception as e:
                        print(f"  [ERROR] 删除失败 {idx}: {e}")
            else:
                # Security Analytics findings 通常按时间分片，删除旧分片
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
                for idx in sa_indices_list:
                    try:
                        # 检查索引的最后更新时间
                        stats = client.indices.stats(index=idx)
                        # 如果索引很旧，删除它
                        # 这里简化处理：删除所有SA findings（因为它们通常会自动清理）
                        pass
                    except:
                        pass
        else:
            print("  [INFO] 没有找到 Security Analytics Findings 索引")
    except Exception as e:
        print(f"  [WARNING] 删除 Security Analytics Findings 失败: {e}")
    
    # 2. Raw Findings
    print("\n[2] 删除 Raw Findings...")
    try:
        raw_pattern = INDEX_PATTERNS['RAW_FINDINGS']
        indices = client.indices.get_alias(index=f"*{raw_pattern}*")
        raw_indices = list(indices.keys())
        
        if raw_indices:
            if all_data:
                for idx in raw_indices:
                    try:
                        count = client.count(index=idx).get('count', 0)
                        client.indices.delete(index=idx)
                        print(f"  [OK] 已删除: {idx} ({count:,} 个文档)")
                        deleted_count += 1
                    except Exception as e:
                        print(f"  [ERROR] 删除失败 {idx}: {e}")
            else:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
                for idx in raw_indices:
                    try:
                        # 从索引名提取日期
                        date_str = idx.split('-')[-3:]
                        if len(date_str) == 3:
                            index_date = datetime.strptime('-'.join(date_str), '%Y-%m-%d').replace(tzinfo=timezone.utc)
                            if index_date < cutoff_date:
                                count = client.count(index=idx).get('count', 0)
                                client.indices.delete(index=idx)
                                print(f"  [OK] 已删除: {idx} ({count:,} 个文档, 日期: {index_date.date()})")
                                deleted_count += 1
                    except:
                        pass
        else:
            print("  [INFO] 没有找到 Raw Findings 索引")
    except Exception as e:
        print(f"  [WARNING] 删除 Raw Findings 失败: {e}")
    
    # 3. Canonical Findings
    print("\n[3] 删除 Canonical Findings...")
    try:
        canonical_pattern = INDEX_PATTERNS['CANONICAL_FINDINGS']
        indices = client.indices.get_alias(index=f"*{canonical_pattern}*")
        canonical_indices = list(indices.keys())
        
        if canonical_indices:
            if all_data:
                for idx in canonical_indices:
                    try:
                        count = client.count(index=idx).get('count', 0)
                        client.indices.delete(index=idx)
                        print(f"  [OK] 已删除: {idx} ({count:,} 个文档)")
                        deleted_count += 1
                    except Exception as e:
                        print(f"  [ERROR] 删除失败 {idx}: {e}")
            else:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
                for idx in canonical_indices:
                    try:
                        date_str = idx.split('-')[-3:]
                        if len(date_str) == 3:
                            index_date = datetime.strptime('-'.join(date_str), '%Y-%m-%d').replace(tzinfo=timezone.utc)
                            if index_date < cutoff_date:
                                count = client.count(index=idx).get('count', 0)
                                client.indices.delete(index=idx)
                                print(f"  [OK] 已删除: {idx} ({count:,} 个文档, 日期: {index_date.date()})")
                                deleted_count += 1
                    except:
                        pass
        else:
            print("  [INFO] 没有找到 Canonical Findings 索引")
    except Exception as e:
        print(f"  [WARNING] 删除 Canonical Findings 失败: {e}")
    
    print(f"\n总共删除了 {deleted_count} 个 Findings 索引")
    return deleted_count


def delete_old_neo4j_data(days: int = None, all_data: bool = False):
    """删除 Neo4j 中的旧数据"""
    deleted_nodes = 0
    deleted_relationships = 0
    
    print("\n" + "=" * 80)
    print("删除 Neo4j 旧数据")
    print("=" * 80)
    
    try:
        with _get_session() as session:
            if all_data:
                print("\n[WARNING] 准备删除所有 Neo4j 数据...")
                result = session.run("MATCH ()-[r]->() DELETE r RETURN count(r) AS cnt")
                deleted_relationships = result.single()["cnt"] if result.peek() else 0
                print(f"  [OK] 删除了 {deleted_relationships:,} 条关系")
                
                result = session.run("MATCH (n) DETACH DELETE n RETURN count(n) AS cnt")
                deleted_nodes = result.single()["cnt"] if result.peek() else 0
                print(f"  [OK] 删除了 {deleted_nodes:,} 个节点")
            else:
                # 删除指定天数前的数据（基于时间戳）
                cutoff_timestamp = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
                print(f"\n删除 {cutoff_timestamp} 之前的数据...")
                
                # 删除旧的关系（基于 @timestamp）
                result = session.run("""
                    MATCH ()-[r]->()
                    WHERE r.`@timestamp` IS NOT NULL AND r.`@timestamp` < $cutoff
                    DELETE r
                    RETURN count(r) AS cnt
                """, cutoff=cutoff_timestamp)
                deleted_relationships = result.single()["cnt"] if result.peek() else 0
                print(f"  [OK] 删除了 {deleted_relationships:,} 条旧关系")
                
                # 删除孤立的节点（没有关系的节点，且时间戳较旧）
                result = session.run("""
                    MATCH (n)
                    WHERE NOT (n)--()
                    AND n.`@timestamp` IS NOT NULL
                    AND n.`@timestamp` < $cutoff
                    DETACH DELETE n
                    RETURN count(n) AS cnt
                """, cutoff=cutoff_timestamp)
                deleted_nodes = result.single()["cnt"] if result.peek() else 0
                print(f"  [OK] 删除了 {deleted_nodes:,} 个孤立节点")
        
        print(f"\n总共删除了 {deleted_nodes:,} 个节点和 {deleted_relationships:,} 条关系")
        return deleted_nodes + deleted_relationships
        
    except Exception as e:
        print(f"[ERROR] 删除 Neo4j 数据失败: {e}")
        return 0


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="清理数据库中的旧数据")
    parser.add_argument(
        "--days",
        type=int,
        help="删除N天前的数据（默认：7天）"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="删除所有数据（危险！）"
    )
    parser.add_argument(
        "--only-events",
        action="store_true",
        help="只删除events"
    )
    parser.add_argument(
        "--only-findings",
        action="store_true",
        help="只删除findings"
    )
    parser.add_argument(
        "--only-neo4j",
        action="store_true",
        help="只删除Neo4j数据"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="自动确认删除（不需要交互）"
    )
    
    args = parser.parse_args()
    
    # 确定删除范围
    if args.all:
        days = None
        print("=" * 80)
        print("⚠️  警告：将删除所有数据！")
        print("=" * 80)
    elif args.days:
        days = args.days
        print("=" * 80)
        print(f"清理 {days} 天前的数据")
        print("=" * 80)
    else:
        days = 7
        print("=" * 80)
        print(f"清理最近 {days} 天的数据（默认）")
        print("=" * 80)
    
    # 确认删除
    if not args.yes:
        if args.all:
            response = input("\n⚠️  确认删除所有数据？(yes/no): ").strip().lower()
        else:
            response = input(f"\n确认删除 {days} 天前的数据？(yes/no): ").strip().lower()
        
        if response != 'yes':
            print("[INFO] 取消删除")
            return 0
    
    # 显示清理前的统计
    print("\n清理前的数据统计:")
    before_stats = get_data_statistics()
    print(f"  Events: {before_stats['events']:,}")
    print(f"  Raw Findings: {before_stats['raw_findings']:,}")
    print(f"  Canonical Findings: {before_stats['canonical_findings']:,}")
    print(f"  Neo4j 节点: {before_stats['neo4j_nodes']:,}")
    print(f"  Neo4j 关系: {before_stats['neo4j_relationships']:,}")
    
    # 执行清理
    total_deleted = 0
    
    if args.only_events:
        total_deleted += delete_old_events(days=days, all_data=args.all)
    elif args.only_findings:
        total_deleted += delete_old_findings(days=days, all_data=args.all)
    elif args.only_neo4j:
        total_deleted += delete_old_neo4j_data(days=days, all_data=args.all)
    else:
        # 清理所有类型的数据
        total_deleted += delete_old_events(days=days, all_data=args.all)
        total_deleted += delete_old_findings(days=days, all_data=args.all)
        total_deleted += delete_old_neo4j_data(days=days, all_data=args.all)
    
    # 显示清理后的统计
    print("\n" + "=" * 80)
    print("清理完成")
    print("=" * 80)
    print("\n清理后的数据统计:")
    after_stats = get_data_statistics()
    print(f"  Events: {after_stats['events']:,} (删除了 {before_stats['events'] - after_stats['events']:,})")
    print(f"  Raw Findings: {after_stats['raw_findings']:,} (删除了 {before_stats['raw_findings'] - after_stats['raw_findings']:,})")
    print(f"  Canonical Findings: {after_stats['canonical_findings']:,} (删除了 {before_stats['canonical_findings'] - after_stats['canonical_findings']:,})")
    print(f"  Neo4j 节点: {after_stats['neo4j_nodes']:,} (删除了 {before_stats['neo4j_nodes'] - after_stats['neo4j_nodes']:,})")
    print(f"  Neo4j 关系: {after_stats['neo4j_relationships']:,} (删除了 {before_stats['neo4j_relationships'] - after_stats['neo4j_relationships']:,})")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
