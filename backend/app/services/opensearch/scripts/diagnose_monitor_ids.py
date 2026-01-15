#!/usr/bin/env python3
"""
诊断脚本：检查为什么找不到 monitor IDs

功能：
1. 检查 .opensearch-sap-detectors-config 索引是否存在
2. 检查detector详情中是否有monitor_id字段
3. 检查monitors API是否可用
4. 提供详细的调试信息
"""

import sys
from pathlib import Path

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client
from app.services.opensearch.analysis import (
    _get_all_monitor_ids,
    _get_detector_details,
    SA_DETECTORS_SEARCH_API,
    DETECTORS_CONFIG_INDEX,
)


def check_config_index():
    """检查配置索引"""
    print("=" * 80)
    print("检查 1: .opensearch-sap-detectors-config 索引")
    print("=" * 80)
    
    client = get_client()
    
    try:
        exists = client.indices.exists(index=DETECTORS_CONFIG_INDEX)
        print(f"\n索引存在: {exists}")
        
        if exists:
            # 查询索引内容
            response = client.transport.perform_request(
                'POST',
                f'/{DETECTORS_CONFIG_INDEX}/_search',
                body={
                    "size": 5,
                    "query": {"match_all": {}}
                }
            )
            hits = response.get('hits', {}).get('hits', [])
            print(f"\n索引中的文档数量: {response.get('hits', {}).get('total', {}).get('value', 0)}")
            
            if hits:
                print(f"\n前 {len(hits)} 个文档的字段:")
                for i, hit in enumerate(hits, 1):
                    src = hit.get('_source', {})
                    print(f"\n  [{i}] 文档ID: {hit.get('_id')}")
                    print(f"      type: {src.get('type')}")
                    print(f"      enabled: {src.get('enabled')}")
                    print(f"      monitor_id: {src.get('monitor_id')}")
                    print(f"      monitor_ids: {src.get('monitor_ids')}")
                    print(f"      所有字段: {list(src.keys())}")
        else:
            print("\n[WARNING] 索引不存在，这是正常的（某些OpenSearch版本可能不使用此索引）")
        
        return exists
        
    except Exception as e:
        print(f"\n[ERROR] 检查索引失败: {e}")
        return False


def check_detector_details():
    """检查detector详情"""
    print("\n" + "=" * 80)
    print("检查 2: Detector 详情中的 monitor_id 字段")
    print("=" * 80)
    
    client = get_client()
    
    try:
        # 获取所有detectors
        detectors_resp = client.transport.perform_request(
            'POST',
            SA_DETECTORS_SEARCH_API,
            body={
                "query": {"match_all": {}},
                "size": 10
            }
        )
        detector_hits = detectors_resp.get('hits', {}).get('hits', [])
        
        print(f"\n找到 {len(detector_hits)} 个detectors")
        
        monitor_ids_found = []
        
        for i, hit in enumerate(detector_hits, 1):
            detector_id = hit.get('_id')
            detector_source = hit.get('_source', {})
            detector_name = detector_source.get('name', 'N/A')
            enabled = detector_source.get('enabled', False)
            
            print(f"\n  [{i}] Detector: {detector_name} (ID: {detector_id[:30]}...)")
            print(f"      启用状态: {enabled}")
            
            # 检查_source中的字段
            monitor_id_in_source = (
                detector_source.get('monitor_id') or 
                detector_source.get('monitorId') or
                detector_source.get('monitor_ids') or
                detector_source.get('monitorIds') or
                detector_source.get('workflow_id') or
                detector_source.get('workflowId')
            )
            
            if monitor_id_in_source:
                print(f"      ✓ 在_source中找到: {monitor_id_in_source}")
                if isinstance(monitor_id_in_source, list):
                    monitor_ids_found.extend(monitor_id_in_source)
                else:
                    monitor_ids_found.append(monitor_id_in_source)
            else:
                print(f"      ✗ _source中没有monitor_id相关字段")
                print(f"      _source的字段: {list(detector_source.keys())[:15]}")
            
            # 尝试获取完整详情
            try:
                detector_detail = _get_detector_details(client, detector_id)
                if detector_detail:
                    monitor_id_in_detail = (
                        detector_detail.get('monitor_id') or 
                        detector_detail.get('monitorId') or
                        detector_detail.get('monitor_ids') or
                        detector_detail.get('monitorIds') or
                        detector_detail.get('workflow_id') or
                        detector_detail.get('workflowId')
                    )
                    
                    if monitor_id_in_detail:
                        print(f"      ✓ 在详情中找到: {monitor_id_in_detail}")
                        if isinstance(monitor_id_in_detail, list):
                            monitor_ids_found.extend(monitor_id_in_detail)
                        else:
                            monitor_ids_found.append(monitor_id_in_detail)
                    else:
                        print(f"      ✗ 详情中也没有monitor_id相关字段")
                        print(f"      详情的字段: {list(detector_detail.keys())[:15]}")
            except Exception as e:
                print(f"      ✗ 获取详情失败: {e}")
        
        if monitor_ids_found:
            print(f"\n[OK] 找到 {len(set(monitor_ids_found))} 个唯一的 monitor IDs")
            return True
        else:
            print(f"\n[WARNING] 未在任何detector中找到monitor_id")
            return False
        
    except Exception as e:
        print(f"\n[ERROR] 检查detector详情失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_monitors_api():
    """检查monitors API"""
    print("\n" + "=" * 80)
    print("检查 3: Monitors API")
    print("=" * 80)
    
    client = get_client()
    
    try:
        # 查询所有monitors
        monitors_resp = client.transport.perform_request(
            'POST',
            '/_plugins/_alerting/monitors/_search',
            body={
                "query": {"match_all": {}},
                "size": 10
            }
        )
        
        monitor_hits = monitors_resp.get('hits', {}).get('hits', [])
        total = monitors_resp.get('hits', {}).get('total', {}).get('value', len(monitor_hits))
        
        print(f"\n找到 {total} 个monitors")
        
        if monitor_hits:
            print(f"\n前 {len(monitor_hits)} 个monitors:")
            for i, hit in enumerate(monitor_hits, 1):
                monitor_id = hit.get('_id')
                source = hit.get('_source', {})
                monitor_name = source.get('name', 'N/A')
                monitor_type = source.get('type', 'N/A')
                
                print(f"\n  [{i}] Monitor ID: {monitor_id}")
                print(f"      名称: {monitor_name}")
                print(f"      类型: {monitor_type}")
                print(f"      字段: {list(source.keys())[:10]}")
            
            print(f"\n[OK] Monitors API可用，找到 {total} 个monitors")
            print(f"[INFO] 可以使用这些monitor IDs来触发扫描")
            return True
        else:
            print(f"\n[WARNING] Monitors API可用，但没有找到任何monitors")
            return False
        
    except Exception as e:
        print(f"\n[ERROR] 检查monitors API失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_get_all_monitor_ids():
    """测试获取monitor IDs的函数"""
    print("\n" + "=" * 80)
    print("检查 4: 测试 _get_all_monitor_ids() 函数")
    print("=" * 80)
    
    client = get_client()
    
    try:
        monitor_ids = _get_all_monitor_ids(client, enabled_only=True)
        
        print(f"\n结果:")
        print(f"  找到 {len(monitor_ids)} 个 monitor IDs")
        
        if monitor_ids:
            print(f"\n  Monitor IDs:")
            for i, mid in enumerate(monitor_ids[:10], 1):
                print(f"    {i}. {mid}")
            if len(monitor_ids) > 10:
                print(f"    ... 还有 {len(monitor_ids) - 10} 个")
            return True
        else:
            print(f"\n  [WARNING] 未找到任何 monitor IDs")
            return False
        
    except Exception as e:
        print(f"\n[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主函数"""
    print("=" * 80)
    print("诊断脚本：检查为什么找不到 monitor IDs")
    print("=" * 80)
    
    results = []
    
    # 执行各项检查
    results.append(("配置索引", check_config_index()))
    results.append(("Detector详情", check_detector_details()))
    results.append(("Monitors API", check_monitors_api()))
    results.append(("获取函数", test_get_all_monitor_ids()))
    
    # 汇总结果
    print("\n" + "=" * 80)
    print("诊断结果汇总")
    print("=" * 80)
    
    for name, result in results:
        status = "✓" if result else "✗"
        print(f"  {status} {name}: {'通过' if result else '失败'}")
    
    # 提供建议
    print("\n" + "=" * 80)
    print("建议")
    print("=" * 80)
    
    if not any(r for _, r in results):
        print("\n[WARNING] 所有检查都失败，可能的原因：")
        print("  1. OpenSearch Security Analytics 插件未正确安装")
        print("  2. Detector未正确创建或配置")
        print("  3. Monitor未正确关联到Detector")
        print("\n[INFO] 即使没有monitor IDs，也可以查询已有findings")
        print("  使用: run_data_analysis(trigger_scan=False)")
    elif results[-1][1]:  # 如果获取函数成功
        print("\n[OK] 可以正常获取monitor IDs，可以触发扫描")
    else:
        print("\n[INFO] 虽然某些检查失败，但monitors API可用")
        print("[INFO] 代码已添加备用方案，应该可以工作")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
