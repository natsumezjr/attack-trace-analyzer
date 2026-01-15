#!/usr/bin/env python3
"""
删除 OpenSearch Security Analytics Detectors

功能：
1. 列出所有 detectors
2. 删除所有 detectors（或指定类型的detector）
3. 可选：只删除特定类型的detector（如windows）
"""

import sys
import argparse
from pathlib import Path

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client

# Security Analytics API
SA_DETECTORS_SEARCH_API = "/_plugins/_security_analytics/detectors/_search"
SA_DETECTOR_DELETE_API = "/_plugins/_security_analytics/detectors/{detector_id}"


def list_all_detectors():
    """列出所有detectors"""
    client = get_client()
    
    try:
        response = client.transport.perform_request(
            'POST',
            SA_DETECTORS_SEARCH_API,
            body={
                "query": {"match_all": {}},
                "size": 1000
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        detectors = []
        
        for hit in hits:
            detector_id = hit.get('_id')
            detector_source = hit.get('_source', {})
            
            detector_info = {
                "id": detector_id,
                "name": detector_source.get('name', 'Unknown'),
                "detector_type": detector_source.get('detector_type', 'Unknown'),
                "enabled": detector_source.get('enabled', False)
            }
            detectors.append(detector_info)
        
        return detectors
    except Exception as e:
        print(f"[ERROR] 获取detectors列表失败: {e}")
        return []


def delete_detector(detector_id: str) -> bool:
    """删除单个detector"""
    client = get_client()
    
    try:
        client.transport.perform_request(
            'DELETE',
            SA_DETECTOR_DELETE_API.format(detector_id=detector_id)
        )
        return True
    except Exception as e:
        print(f"[ERROR] 删除detector失败 {detector_id}: {e}")
        return False


def delete_all_detectors(filter_type: str = None, auto_confirm: bool = False):
    """删除所有detectors（可选：只删除特定类型）"""
    client = get_client()
    
    print("=" * 80)
    if filter_type:
        print(f"删除所有 {filter_type} 类型的 Detectors")
    else:
        print("删除所有 Detectors")
    print("=" * 80)
    
    # 1. 列出所有detectors
    print("\n[1] 查询所有 detectors...")
    detectors = list_all_detectors()
    
    if not detectors:
        print("  [INFO] 没有找到任何 detectors")
        return
    
    print(f"  找到 {len(detectors)} 个 detectors:")
    for det in detectors:
        print(f"    - {det['name']} (ID: {det['id'][:50]}..., Type: {det['detector_type']}, Enabled: {det['enabled']})")
    
    # 2. 过滤detectors（如果指定了类型）
    detectors_to_delete = detectors
    if filter_type:
        detectors_to_delete = [d for d in detectors if d['detector_type'].lower() == filter_type.lower()]
        print(f"\n[2] 过滤后，需要删除 {len(detectors_to_delete)} 个 {filter_type} 类型的 detectors:")
        for det in detectors_to_delete:
            print(f"    - {det['name']} (ID: {det['id'][:50]}...)")
    
    if not detectors_to_delete:
        print("\n[INFO] 没有需要删除的 detectors")
        return
    
    # 3. 确认删除（如果未使用--yes参数）
    if not hasattr(delete_all_detectors, '_auto_confirm'):
        print(f"\n[3] 准备删除 {len(detectors_to_delete)} 个 detectors...")
        response = input("  确认删除？(yes/no): ").strip().lower()
        if response != 'yes':
            print("  [INFO] 取消删除")
            return
    
    # 4. 删除detectors
    print(f"\n[4] 开始删除 detectors...")
    deleted_count = 0
    failed_count = 0
    
    for det in detectors_to_delete:
        detector_id = det['id']
        detector_name = det['name']
        
        print(f"  删除: {detector_name} (ID: {detector_id[:50]}...)")
        if delete_detector(detector_id):
            print(f"    [OK] 已删除")
            deleted_count += 1
        else:
            print(f"    [ERROR] 删除失败")
            failed_count += 1
    
    # 5. 总结
    print("\n" + "=" * 80)
    print("删除完成")
    print("=" * 80)
    print(f"  成功删除: {deleted_count} 个")
    print(f"  删除失败: {failed_count} 个")
    print(f"  总计: {len(detectors_to_delete)} 个")


def main():
    parser = argparse.ArgumentParser(description="删除 OpenSearch Security Analytics Detectors")
    parser.add_argument(
        "--type",
        type=str,
        help="只删除指定类型的detector（如：windows, linux, dns, network）"
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="只列出detectors，不删除"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="自动确认删除（不需要交互确认）"
    )
    
    args = parser.parse_args()
    
    if args.list_only:
        print("=" * 80)
        print("Detectors 列表")
        print("=" * 80)
        detectors = list_all_detectors()
        if detectors:
            print(f"\n找到 {len(detectors)} 个 detectors:\n")
            for det in detectors:
                print(f"  - {det['name']}")
                print(f"    ID: {det['id']}")
                print(f"    Type: {det['detector_type']}")
                print(f"    Enabled: {det['enabled']}")
                print()
        else:
            print("\n[INFO] 没有找到任何 detectors")
    else:
        delete_all_detectors(filter_type=args.type, auto_confirm=args.yes)


if __name__ == "__main__":
    main()
