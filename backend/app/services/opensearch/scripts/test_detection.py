#!/usr/bin/env python3
"""
使用现有 Detector 运行检测测试脚本

功能：
1. 列出所有可用的 detector
2. 使用所有 detector 运行检测（或指定detector）
3. 显示检测结果和 findings 统计
4. 运行完整分析（检测 + 去重）
"""

import sys
import argparse
from pathlib import Path

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client
from app.services.opensearch.analysis import (
    run_security_analytics,
    run_data_analysis,
    SA_FINDINGS_SEARCH_API,
    _get_detector_details,
    _trigger_scan_with_lock,
    _should_trigger_scan,
    _fetch_and_store_findings,
    _get_latest_findings_count,
    _get_latest_findings_timestamp,
)
from app.services.opensearch.trigger_lock import complete_trigger


def run_detector_scan(detector_id: str, detector_name: str, trigger_scan: bool = True, max_wait_seconds: int = 120) -> dict:
    """运行单个detector的检测"""
    client = get_client()
    
    try:
        # 查询已有findings的时间戳和数量
        baseline_timestamp_ms, baseline_count = _get_latest_findings_timestamp(client, detector_id)
        
        # 判断是否需要触发新扫描
        need_trigger = _should_trigger_scan(trigger_scan, baseline_count)
        source = "cached_findings" if baseline_count > 0 else "no_findings"
        
        scan_info = {
            "scan_requested": False,
            "scan_completed": False,
            "scan_wait_ms": 0,
            "source": source
        }
        
        if need_trigger:
            detector = _get_detector_details(client, detector_id)
            if detector:
                try:
                    scan_info = _trigger_scan_with_lock(
                        client, detector_id, detector, baseline_timestamp_ms, baseline_count, max_wait_seconds
                    )
                except Exception as trigger_error:
                    print(f"[WARNING] 触发检测时出错: {trigger_error}")
                    complete_trigger(detector_id)
        
        # 查询并存储findings
        storage_result = _fetch_and_store_findings(client, detector_id, only_new=True)
        
        return {
            "success": storage_result["success"],
            "detector_id": detector_id,
            "detector_name": detector_name,
            "findings_count": storage_result["findings_count"],
            "new_findings_count": storage_result.get("new_findings_count", storage_result["findings_count"]),
            "stored": storage_result["stored"],
            "failed": storage_result.get("failed", 0),
            "duplicated": storage_result.get("duplicated", 0),
            **scan_info
        }
    except Exception as e:
        return {
            "success": False,
            "detector_id": detector_id,
            "detector_name": detector_name,
            "error": str(e),
            "findings_count": 0,
            "stored": 0
        }


def list_detectors():
    """列出所有 detector"""
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
        print(f"❌ 获取 detector 列表失败: {e}")
        return []


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="使用现有 Detector 运行检测")
    parser.add_argument(
        "--all",
        action="store_true",
        help="运行所有启用的 detector（默认：只运行第一个）"
    )
    parser.add_argument(
        "--detector-id",
        type=str,
        help="指定要运行的 detector ID"
    )
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="不触发新扫描，只使用已有 findings"
    )
    args = parser.parse_args()
    
    print("=" * 80)
    print("使用现有 Detector 运行检测")
    print("=" * 80)
    
    # 1. 列出所有 detector
    print("\n[步骤 1] 列出所有 Detector...")
    detectors = list_detectors()
    
    if not detectors:
        print("[ERROR] 未找到任何 detector")
        print("\n请先创建 detector:")
        print("  cd backend")
        print("  uv run python opensearch/scripts/setup_security_analytics.py --multiple")
        return 1
    
    print(f"\n[OK] 找到 {len(detectors)} 个 Detector:")
    for i, det in enumerate(detectors, 1):
        det_id = det.get('_id', 'N/A')
        det_name = det.get('name', 'N/A')
        det_type = det.get('detector_type', 'N/A')
        det_enabled = det.get('enabled', False)
        status = "[ENABLED] 启用" if det_enabled else "[DISABLED] 禁用"
        
        # 获取规则数量
        inputs = det.get('inputs', [])
        rules_count = 0
        if inputs:
            detector_input = inputs[0].get('detector_input', {})
            prepackaged = detector_input.get('pre_packaged_rules', [])
            custom = detector_input.get('custom_rules', [])
            rules_count = len(prepackaged) + len(custom)
        
        print(f"\n  {i}. {det_name}")
        print(f"     ID: {det_id}")
        print(f"     类型: {det_type}")
        print(f"     状态: {status}")
        print(f"     规则数量: {rules_count} 个")
    
    # 2. 选择要运行的 detector
    enabled_detectors = [d for d in detectors if d.get('enabled', False)]
    
    if not enabled_detectors:
        print("\n[ERROR] 没有启用的 detector")
        return 1
    
    detectors_to_run = []
    if args.detector_id:
        # 指定detector ID
        found = next((d for d in enabled_detectors if d.get('_id') == args.detector_id), None)
        if found:
            detectors_to_run = [found]
        else:
            print(f"\n[ERROR] 未找到指定的 detector ID: {args.detector_id}")
            return 1
    elif args.all:
        # 运行所有启用的detector
        detectors_to_run = enabled_detectors
        print(f"\n[OK] 将运行所有 {len(detectors_to_run)} 个启用的 detector")
    else:
        # 默认：只运行第一个
        detectors_to_run = [enabled_detectors[0]]
        print(f"\n提示: 将使用第一个启用的 detector（使用 --all 运行所有detector）")
    
    # 3. 运行检测
    print("\n" + "=" * 80)
    print(f"[步骤 2] 运行 Security Analytics 检测（{len(detectors_to_run)} 个 detector）...")
    print("=" * 80)
    
    trigger_scan = not args.no_scan
    all_results = []
    
    for i, det in enumerate(detectors_to_run, 1):
        det_id = det.get('_id')
        det_name = det.get('name')
        det_type = det.get('detector_type')
        
        print(f"\n[{i}/{len(detectors_to_run)}] 运行 detector: {det_name} (类型: {det_type})")
        print("-" * 80)
        
        try:
            # 增加等待时间，确保扫描完成（3分钟）
            result = run_detector_scan(det_id, det_name, trigger_scan=trigger_scan, max_wait_seconds=180)
            all_results.append(result)
            
            print(f"  成功: {'[OK]' if result.get('success') else '[FAIL]'}")
            print(f"  Findings 数量: {result.get('findings_count', 0)}")
            print(f"  新 Findings: {result.get('new_findings_count', 0)}")
            print(f"  存储成功: {result.get('stored', 0)}")
            print(f"  存储失败: {result.get('failed', 0)}")
            print(f"  重复跳过: {result.get('duplicated', 0)}")
            
            if result.get('error'):
                print(f"  错误: {result.get('error')}")
        except Exception as e:
            print(f"  [ERROR] 检测失败: {e}")
            all_results.append({
                "success": False,
                "detector_name": det_name,
                "error": str(e)
            })
    
    # 4. 汇总结果
    print("\n" + "=" * 80)
    print("检测结果汇总")
    print("=" * 80)
    
    total_findings = sum(r.get('findings_count', 0) for r in all_results)
    total_stored = sum(r.get('stored', 0) for r in all_results)
    total_failed = sum(r.get('failed', 0) for r in all_results)
    successful_detectors = sum(1 for r in all_results if r.get('success'))
    
    print(f"\n总计:")
    print(f"  成功运行的 detector: {successful_detectors}/{len(detectors_to_run)}")
    print(f"  总 Findings 数量: {total_findings}")
    print(f"  总存储成功: {total_stored}")
    print(f"  总存储失败: {total_failed}")
    
    print(f"\n各 Detector 详情:")
    for result in all_results:
        det_name = result.get('detector_name', 'Unknown')
        findings = result.get('findings_count', 0)
        stored = result.get('stored', 0)
        status = "[OK]" if result.get('success') else "[FAIL]"
        print(f"  {status} {det_name}: {findings} 个 findings, 存储 {stored} 个")
    
    # 5. 运行完整分析（检测 + 去重）
    if total_findings > 0:
        print("\n" + "=" * 80)
        print("[步骤 3] 运行完整分析（检测 + 去重）...")
        print("=" * 80)
        
        print("\n开始完整分析（汇总所有detector的findings）...")
        try:
            analysis_result = run_data_analysis(trigger_scan=False)  # 使用已有findings，不触发新扫描
            
            print("\n" + "-" * 80)
            print("完整分析结果:")
            print("-" * 80)
            
            detection = analysis_result.get('detection', {})
            deduplication = analysis_result.get('deduplication', {})
            
            print("\n检测阶段:")
            print(f"  Findings 数量: {detection.get('findings_count', 0)}")
            print(f"  存储成功: {detection.get('stored', 0)}")
            
            print("\n去重阶段:")
            print(f"  原始 Findings: {deduplication.get('total', 0)}")
            print(f"  合并数量: {deduplication.get('merged', 0)}")
            print(f"  Canonical Findings: {deduplication.get('canonical', 0)}")
            print(f"  错误: {deduplication.get('errors', 0)}")
            
            if deduplication.get('canonical', 0) > 0:
                print("\n[OK] 检测和去重完成！")
            else:
                print("\n[WARNING] 检测完成，但没有生成 Canonical Findings")
        except Exception as e:
            print(f"\n[WARNING] 去重阶段失败: {e}")
    
    print("\n" + "=" * 80)
    print("检测完成！")
    print("=" * 80)
    
    return 0 if successful_detectors > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
