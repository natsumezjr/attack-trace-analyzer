#!/usr/bin/env python3
"""
直接调用 analysis.py 中的函数

功能：
1. 直接调用 run_security_analytics() 运行检测
2. 直接调用 run_data_analysis() 运行完整分析（检测+去重）
3. 直接调用 deduplicate_findings() 运行去重
4. 查看结果和tactic提取
"""

import sys
from pathlib import Path

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from opensearch import get_client
from opensearch.analysis import (
    run_security_analytics,
    run_data_analysis,
    deduplicate_findings,
    _convert_security_analytics_finding_to_ecs,
)


def list_detectors():
    """列出所有detector"""
    client = get_client()
    try:
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={
                "query": {"match_all": {}},
                "size": 100
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        detectors = []
        for hit in hits:
            detector = hit.get('_source', {})
            detector['_id'] = hit.get('_id')
            detectors.append(detector)
        return detectors
    except Exception as e:
        print(f"[ERROR] 获取detector列表失败: {e}")
        return []


def run_detection_direct():
    """直接调用run_security_analytics运行检测"""
    print("=" * 80)
    print("直接调用 run_security_analytics() 运行检测")
    print("=" * 80)
    
    # 列出所有detector
    print("\n[1] 列出所有Detector...")
    detectors = list_detectors()
    
    if not detectors:
        print("[ERROR] 未找到任何detector")
        return None
    
    enabled_detectors = [d for d in detectors if d.get('enabled', False)]
    print(f"\n找到 {len(detectors)} 个Detector，其中 {len(enabled_detectors)} 个已启用")
    
    if not enabled_detectors:
        print("[ERROR] 没有启用的detector")
        return None
    
    # 运行检测（使用第一个启用的detector）
    detector = enabled_detectors[0]
    detector_id = detector.get('_id')
    detector_name = detector.get('name', 'Unknown')
    
    print(f"\n[2] 运行检测...")
    print(f"    Detector: {detector_name} (ID: {detector_id})")
    
    try:
        result = run_security_analytics(
            detector_id=detector_id,
            trigger_scan=True,
            max_wait_seconds=180
        )
        
        print(f"\n[3] 检测结果:")
        print(f"    成功: {result.get('success', False)}")
        print(f"    Findings数量: {result.get('findings_count', 0)}")
        print(f"    存储成功: {result.get('stored', 0)}")
        print(f"    存储失败: {result.get('failed', 0)}")
        print(f"    重复跳过: {result.get('duplicated', 0)}")
        
        return result
    except Exception as e:
        print(f"[ERROR] 检测失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_analysis_direct():
    """直接调用run_data_analysis运行完整分析"""
    print("\n" + "=" * 80)
    print("直接调用 run_data_analysis() 运行完整分析（检测+去重）")
    print("=" * 80)
    
    # 检查是否有Events
    from opensearch import get_index_name, INDEX_PATTERNS
    from datetime import datetime
    
    client = get_client()
    today = datetime.now()
    events_index = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    
    if client.indices.exists(index=events_index):
        try:
            stats = client.count(index=events_index)
            event_count = stats.get('count', 0)
            print(f"\n[INFO] 找到Events索引: {events_index}")
            print(f"       事件数量: {event_count:,}")
        except:
            pass
    
    # 检查Raw Findings索引是否存在
    raw_index = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    raw_exists_before = client.indices.exists(index=raw_index)
    
    if raw_exists_before:
        try:
            stats = client.count(index=raw_index)
            raw_count_before = stats.get('count', 0)
            print(f"\n[INFO] Raw Findings索引已存在: {raw_index}")
            print(f"       现有Raw Findings数量: {raw_count_before:,}")
        except:
            raw_count_before = 0
    else:
        raw_count_before = 0
        print(f"\n[INFO] Raw Findings索引不存在，将从Events中提取")
    
    try:
        print(f"\n[INFO] 开始运行检测和分析...")
        result = run_data_analysis(trigger_scan=True)
        
        print("\n" + "=" * 80)
        print("[完整分析结果]")
        print("=" * 80)
        
        detection = result.get('detection', {})
        deduplication = result.get('deduplication', {})
        
        print("\n检测阶段:")
        print(f"  Findings数量: {detection.get('findings_count', 0)}")
        print(f"  存储成功: {detection.get('stored', 0)}")
        print(f"  存储失败: {detection.get('failed', 0)}")
        
        # 检查Raw Findings是否增加
        raw_exists_after = client.indices.exists(index=raw_index)
        if raw_exists_after:
            try:
                stats = client.count(index=raw_index)
                raw_count_after = stats.get('count', 0)
                new_raw_count = raw_count_after - raw_count_before
                print(f"\n  Raw Findings变化:")
                print(f"    之前: {raw_count_before:,}")
                print(f"    之后: {raw_count_after:,}")
                print(f"    新增: {new_raw_count:,}")
            except:
                pass
        
        print("\n去重阶段:")
        print(f"  原始Findings: {deduplication.get('total', 0)}")
        print(f"  合并数量: {deduplication.get('merged', 0)}")
        print(f"  Canonical Findings: {deduplication.get('canonical', 0)}")
        print(f"  错误: {deduplication.get('errors', 0)}")
        
        return result
    except Exception as e:
        print(f"[ERROR] 完整分析失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_deduplication_direct():
    """直接调用deduplicate_findings运行去重"""
    print("\n" + "=" * 80)
    print("直接调用 deduplicate_findings() 运行去重")
    print("=" * 80)
    
    try:
        result = deduplicate_findings()
        
        print("\n[去重结果]")
        print("-" * 80)
        print(f"  原始Findings: {result.get('total', 0)}")
        print(f"  合并数量: {result.get('merged', 0)}")
        print(f"  Canonical Findings: {result.get('canonical', 0)}")
        print(f"  错误: {result.get('errors', 0)}")
        
        return result
    except Exception as e:
        print(f"[ERROR] 去重失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def check_tactic_extraction_direct():
    """直接检查tactic提取"""
    print("\n" + "=" * 80)
    print("检查 Tactic 提取")
    print("=" * 80)
    
    from opensearch import get_index_name, INDEX_PATTERNS
    from datetime import datetime
    
    client = get_client()
    today = datetime.now()
    raw_index = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    
    if not client.indices.exists(index=raw_index):
        print("\n[WARNING] Raw Findings索引不存在")
        return
    
    try:
        response = client.search(
            index=raw_index,
            body={
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        
        if not hits:
            print("\n[WARNING] 没有找到Raw Findings")
            return
        
        print(f"\n找到 {len(hits)} 个Raw Findings，检查前10个:")
        print("-" * 80)
        
        tactic_stats = {}
        unknown_count = 0
        
        for i, hit in enumerate(hits[:10], 1):
            finding = hit.get('_source', {})
            finding_id = finding.get('event', {}).get('id', 'N/A')[:30]
            
            threat = finding.get('threat', {})
            tactic = threat.get('tactic', {})
            tactic_id = tactic.get('id', 'N/A')
            tactic_name = tactic.get('name', 'N/A')
            
            rule_name = finding.get('rule', {}).get('name', 'N/A')
            
            print(f"\n[{i}] Finding ID: {finding_id}...")
            print(f"    规则: {rule_name}")
            print(f"    Tactic ID: {tactic_id}")
            print(f"    Tactic Name: {tactic_name}")
            
            if tactic_id == "TA0000" or tactic_name == "Unknown":
                unknown_count += 1
                print(f"    [WARNING] Tactic未提取（使用默认值）")
            else:
                print(f"    [OK] Tactic已提取")
                tactic_stats[tactic_id] = tactic_stats.get(tactic_id, 0) + 1
        
        print("\n" + "-" * 80)
        print("统计信息")
        print("-" * 80)
        
        if tactic_stats:
            print(f"\nTactic分布:")
            for tactic_id, count in sorted(tactic_stats.items(), key=lambda x: -x[1]):
                print(f"  {tactic_id}: {count} 个findings")
        
        print(f"\n未提取Tactic的findings: {unknown_count}/{len(hits)}")
        
        if unknown_count == 0:
            print("\n[OK] 所有findings的tactic都已正确提取！")
        else:
            print(f"\n[WARNING] 有 {unknown_count} 个findings的tactic未提取")
        
    except Exception as e:
        print(f"[ERROR] 查询失败: {e}")
        import traceback
        traceback.print_exc()


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="直接调用analysis.py中的函数")
    parser.add_argument(
        "--detection",
        action="store_true",
        help="运行检测（run_security_analytics）"
    )
    parser.add_argument(
        "--analysis",
        action="store_true",
        help="运行完整分析（run_data_analysis）"
    )
    parser.add_argument(
        "--deduplication",
        action="store_true",
        help="运行去重（deduplicate_findings）"
    )
    parser.add_argument(
        "--tactic",
        action="store_true",
        help="检查tactic提取"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="运行所有步骤（检测+分析+检查tactic）"
    )
    
    args = parser.parse_args()
    
    # 如果没有指定任何选项，默认运行所有
    if not any([args.detection, args.analysis, args.deduplication, args.tactic, args.all]):
        args.all = True
    
    if args.all:
        # 运行完整流程
        run_analysis_direct()  # 这会运行检测+去重
        check_tactic_extraction_direct()
    else:
        # 运行指定步骤
        if args.detection:
            run_detection_direct()
        
        if args.analysis:
            run_analysis_direct()
        
        if args.deduplication:
            run_deduplication_direct()
        
        if args.tactic:
            check_tactic_extraction_direct()
    
    print("\n" + "=" * 80)
    print("完成")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
