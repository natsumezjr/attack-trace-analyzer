#!/usr/bin/env python3
"""
统一的检查脚本（合并了所有检查功能）

功能：
1. 检查OpenSearch集群健康状态
2. 检查JVM内存使用情况
3. 检查detectors状态
4. 检查findings类型分布
5. 检查events分布
6. 检查correlation状态

使用方法:
    # 检查所有
    uv run python consolidated_check.py
    
    # 只检查健康状态
    uv run python consolidated_check.py --health
    
    # 只检查findings
    uv run python consolidated_check.py --findings
    
    # 只检查detectors
    uv run python consolidated_check.py --detectors
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS
from app.services.opensearch.analysis import SA_FINDINGS_SEARCH_API


def check_cluster_health():
    """检查集群健康状态"""
    client = get_client()
    
    print("=" * 80)
    print("集群健康状态")
    print("=" * 80)
    
    try:
        health = client.cluster.health()
        status = health.get('status', 'unknown')
        print(f"\n状态: {status}")
        print(f"节点数: {health.get('number_of_nodes', 'N/A')}")
        print(f"数据节点数: {health.get('number_of_data_nodes', 'N/A')}")
        print(f"活动分片: {health.get('active_primary_shards', 'N/A')}")
        print(f"活动分片总数: {health.get('active_shards', 'N/A')}")
        print(f"未分配分片: {health.get('unassigned_shards', 'N/A')}")
        
        if status == 'red':
            print("\n[ERROR] 集群状态为RED，有严重问题！")
        elif status == 'yellow':
            print("\n[WARNING] 集群状态为YELLOW，有未分配的分片")
        else:
            print("\n[OK] 集群状态正常")
        
        return health
    except Exception as e:
        print(f"\n[ERROR] 查询集群健康失败: {e}")
        return None


def check_jvm_memory():
    """检查JVM内存使用情况"""
    client = get_client()
    
    print("\n" + "=" * 80)
    print("JVM内存使用情况")
    print("=" * 80)
    
    try:
        stats = client.nodes.stats(jvm=True)
        nodes = stats.get('nodes', {})
        
        for node_id, node_stats in nodes.items():
            jvm = node_stats.get('jvm', {})
            mem = jvm.get('mem', {})
            heap_used = mem.get('heap_used_in_bytes', 0)
            heap_max = mem.get('heap_max_in_bytes', 0)
            heap_used_mb = heap_used / 1024 / 1024
            heap_max_mb = heap_max / 1024 / 1024
            heap_percent = (heap_used / heap_max * 100) if heap_max > 0 else 0
            
            print(f"\n节点 {node_id[:20]}...:")
            print(f"  堆内存使用: {heap_used_mb:.1f} MB / {heap_max_mb:.1f} MB ({heap_percent:.1f}%)")
            
            if heap_max_mb < 2000:
                print(f"  [WARNING] JVM堆内存只有{heap_max_mb:.1f}MB，建议增加到2GB")
            elif heap_percent > 90:
                print(f"  [WARNING] 堆内存使用率超过90%，接近OOM！")
            elif heap_percent > 75:
                print(f"  [WARNING] 堆内存使用率超过75%，需要关注")
            else:
                print(f"  [OK] 堆内存使用率正常")
            
            # GC统计
            gc = jvm.get('gc', {})
            collectors = gc.get('collectors', {})
            if collectors:
                print(f"  GC统计:")
                for collector_name, collector_stats in collectors.items():
                    collection_count = collector_stats.get('collection_count', 0)
                    collection_time_ms = collector_stats.get('collection_time_in_millis', 0)
                    print(f"    {collector_name}: {collection_count} 次, 总耗时 {collection_time_ms}ms")
        
    except Exception as e:
        print(f"\n[ERROR] 查询JVM统计失败: {e}")


def check_detectors():
    """检查detectors状态"""
    client = get_client()
    
    print("\n" + "=" * 80)
    print("Detectors 状态")
    print("=" * 80)
    
    try:
        resp = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={'query': {'match_all': {}}, 'size': 100}
        )
        
        hits = resp.get('hits', {}).get('hits', [])
        total = resp.get('hits', {}).get('total', {}).get('value', len(hits))
        
        print(f"\n找到 {total} 个 detectors")
        
        if hits:
            detectors_by_type = {}
            enabled_count = 0
            
            for hit in hits:
                detector_id = hit.get('_id')
                source = hit.get('_source', {})
                detector_name = source.get('name', 'Unknown')
                detector_type = source.get('detector_type', 'Unknown')
                enabled = source.get('enabled', False)
                
                if enabled:
                    enabled_count += 1
                
                if detector_type not in detectors_by_type:
                    detectors_by_type[detector_type] = []
                
                detectors_by_type[detector_type].append({
                    'id': detector_id,
                    'name': detector_name,
                    'enabled': enabled
                })
            
            print(f"\n按类型分组:")
            for detector_type, detectors in sorted(detectors_by_type.items()):
                enabled_in_type = sum(1 for d in detectors if d['enabled'])
                print(f"\n  {detector_type.upper()}: {len(detectors)} 个detectors ({enabled_in_type} 个启用)")
                for det in detectors[:3]:  # 只显示前3个
                    status = "[启用]" if det['enabled'] else "[禁用]"
                    print(f"    {status} {det['name']}")
            
            print(f"\n总结:")
            print(f"  总detectors数: {total}")
            print(f"  启用的detectors: {enabled_count}")
            print(f"  禁用的detectors: {total - enabled_count}")
            
    except Exception as e:
        print(f"\n[ERROR] 查询detectors失败: {e}")


def check_findings():
    """检查findings类型分布"""
    client = get_client()
    
    print("\n" + "=" * 80)
    print("Findings 类型分布")
    print("=" * 80)
    
    try:
        # 先从raw-findings索引查询（更可靠）
        today = datetime.now(timezone.utc)
        idx = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
        
        try:
            resp = client.search(index=idx, body={
                'query': {
                    'range': {
                        '@timestamp': {
                            'gte': (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
                        }
                    }
                },
                'size': 0,
                'aggs': {
                    'by_detector': {
                        'terms': {'field': 'rule.detector_id.keyword', 'size': 20}
                    },
                    'by_log_type': {
                        'terms': {'field': 'log_type.keyword', 'size': 20}
                    },
                    'by_severity': {
                        'terms': {'field': 'event.severity', 'size': 10}
                    }
                }
            })
            
            total = resp.get('hits', {}).get('total', {}).get('value', 0)
            print(f"\n从raw-findings索引获取到 {total} 个findings（最近24小时）")
            
            if total > 0:
                print("\n按Detector分布:")
                for b in resp.get('aggregations', {}).get('by_detector', {}).get('buckets', []):
                    print(f"  {b['key']}: {b['doc_count']} 个")
                
                print("\n按Log Type分布:")
                for b in resp.get('aggregations', {}).get('by_log_type', {}).get('buckets', []):
                    print(f"  {b['key']}: {b['doc_count']} 个")
                
                print("\n按严重性分布:")
                for b in resp.get('aggregations', {}).get('by_severity', {}).get('buckets', []):
                    print(f"  Severity {b['key']}: {b['doc_count']} 个")
        except Exception as e1:
            print(f"\n[WARNING] 从raw-findings索引查询失败: {e1}")
            print("[INFO] 尝试从Security Analytics API查询...")
            
            # 回退到Security Analytics API
            resp = client.transport.perform_request(
                'GET',
                SA_FINDINGS_SEARCH_API,
                params={'size': 200}
            )
            
            findings = resp.get('findings', [])
            total = len(findings)
            
            print(f"\n从Security Analytics API获取到 {total} 个findings")
            
            if findings:
                detector_stats = {}
                log_type_stats = {}
                
                for finding in findings:
                    detector_id = finding.get('detectorId', 'Unknown')
                    log_type = finding.get('logType', 'Unknown')
                    
                    detector_stats[detector_id] = detector_stats.get(detector_id, 0) + 1
                    log_type_stats[log_type] = log_type_stats.get(log_type, 0) + 1
                
                print("\n按Detector分布:")
                for detector_id, count in sorted(detector_stats.items(), key=lambda x: -x[1])[:10]:
                    print(f"  {detector_id[:50]}...: {count} 个")
                
                print("\n按Log Type分布:")
                for log_type, count in sorted(log_type_stats.items(), key=lambda x: -x[1]):
                    print(f"  {log_type}: {count} 个")
                
                print(f"\n[INFO] 有 {len(detector_stats)} 个不同的detectors生成了findings")
                print(f"[INFO] 有 {len(log_type_stats)} 个不同的log types")
                
                if len(detector_stats) > 1:
                    print(f"\n[OK] 有多个detectors在生成findings！")
                else:
                    print(f"\n[WARNING] 只有一个detector在生成findings")
            else:
                print("\n[WARNING] 没有找到findings")
            
    except Exception as e:
        print(f"\n[ERROR] 查询findings失败: {e}")


def check_events():
    """检查events分布"""
    client = get_client()
    today = datetime.now(timezone.utc)
    idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    
    print("\n" + "=" * 80)
    print("Events 分布")
    print("=" * 80)
    
    try:
        resp = client.search(index=idx, body={
            'size': 0,
            'aggs': {
                'by_dataset': {
                    'terms': {'field': 'event.dataset.keyword', 'size': 10}
                },
                'by_category': {
                    'terms': {'field': 'event.category.keyword', 'size': 10}
                }
            }
        })
        
        total = resp.get('hits', {}).get('total', {}).get('value', 0)
        print(f"\n索引: {idx}")
        print(f"Events总数: {total}")
        
        if total > 0:
            print("\n按dataset分布:")
            for b in resp.get('aggregations', {}).get('by_dataset', {}).get('buckets', []):
                print(f"  {b['key']}: {b['doc_count']} 个")
            
            print("\n按category分布:")
            for b in resp.get('aggregations', {}).get('by_category', {}).get('buckets', []):
                print(f"  {b['key']}: {b['doc_count']} 个")
        else:
            print("\n[WARNING] 索引中没有events")
            
    except Exception as e:
        print(f"\n[ERROR] 查询events失败: {e}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="统一的检查脚本")
    parser.add_argument(
        "--health",
        action="store_true",
        help="只检查集群健康状态"
    )
    parser.add_argument(
        "--jvm",
        action="store_true",
        help="只检查JVM内存"
    )
    parser.add_argument(
        "--detectors",
        action="store_true",
        help="只检查detectors状态"
    )
    parser.add_argument(
        "--findings",
        action="store_true",
        help="只检查findings"
    )
    parser.add_argument(
        "--events",
        action="store_true",
        help="只检查events"
    )
    
    args = parser.parse_args()
    
    # 如果没有指定任何选项，检查所有
    check_all = not any([args.health, args.jvm, args.detectors, args.findings, args.events])
    
    if check_all or args.health:
        check_cluster_health()
    
    if check_all or args.jvm:
        check_jvm_memory()
    
    if check_all or args.detectors:
        check_detectors()
    
    if check_all or args.findings:
        check_findings()
    
    if check_all or args.events:
        check_events()
    
    print("\n" + "=" * 80)
    print("检查完成")
    print("=" * 80)


if __name__ == "__main__":
    main()
