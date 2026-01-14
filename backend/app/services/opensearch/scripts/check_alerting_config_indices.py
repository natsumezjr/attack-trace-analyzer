#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查 Alerting 配置索引

用途：检查哪个 config index 可用，用于权限配置

使用方法：
    python check_alerting_config_indices.py
"""

import sys
import os
import json

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client, reset_client


def check_index_search(client, index_name: str):
    """检查索引搜索"""
    try:
        resp = client.transport.perform_request(
            'GET',
            f'/{index_name}/_search',
            params={'size': 1}
        )
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def main():
    print("=" * 60)
    print("检查 Alerting 配置索引")
    print("=" * 60)
    
    reset_client()
    client = get_client()
    
    indices_to_check = [
        ".opendistro-alerting-config",
        ".opensearch-alerting-config"
    ]
    
    results = {}
    
    for index_name in indices_to_check:
        print(f"\n检查索引: {index_name}")
        print("-" * 60)
        
        success, resp, error = check_index_search(client, index_name)
        
        if success:
            print(f"[OK] GET {index_name}/_search 成功")
            print("\n响应内容:")
            print(json.dumps(resp, indent=2, ensure_ascii=False))
            
            # 提取关键信息
            hits = resp.get('hits', {}).get('hits', [])
            total = resp.get('hits', {}).get('total', {})
            if isinstance(total, dict):
                total_value = total.get('value', 0)
            else:
                total_value = total
            
            print(f"\n关键信息:")
            print(f"  总文档数: {total_value}")
            print(f"  返回文档数: {len(hits)}")
            
            if hits:
                doc = hits[0].get('_source', {})
                print(f"  第一个文档的keys: {list(doc.keys())[:10]}")
            
            results[index_name] = {
                "success": True,
                "total": total_value,
                "hits_count": len(hits)
            }
        else:
            print(f"[X] GET {index_name}/_search 失败")
            print(f"错误信息: {error}")
            results[index_name] = {
                "success": False,
                "error": error
            }
    
    # 总结
    print("\n" + "=" * 60)
    print("总结")
    print("=" * 60)
    
    for index_name, result in results.items():
        if result["success"]:
            print(f"[OK] {index_name}: 可用（文档数: {result.get('total', 0)}）")
        else:
            error_msg = result.get("error", "未知错误")
            if "404" in error_msg or "not found" in error_msg.lower():
                print(f"[X] {index_name}: 索引不存在（404）")
            elif "403" in error_msg or "forbidden" in error_msg.lower():
                print(f"[X] {index_name}: 权限不足（403）")
            else:
                print(f"[X] {index_name}: 失败 - {error_msg}")
    
    # 判断哪个索引可用
    available_indices = [name for name, result in results.items() if result.get("success")]
    if available_indices:
        print(f"\n[INFO] 可用的配置索引: {', '.join(available_indices)}")
        print(f"[INFO] 建议在 role 中配置这些索引的权限")
    else:
        print(f"\n[WARNING] 没有找到可用的配置索引")
        print(f"[WARNING] 可能需要检查权限配置或索引是否存在")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
