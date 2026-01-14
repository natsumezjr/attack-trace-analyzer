#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试系统索引访问权限

用途：验证 system:admin/system_index 权限是否生效

使用方法：
    python test_system_index_access.py
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


def test_index_get(client, index_name: str, doc_id: str):
    """测试直接 GET 文档"""
    try:
        resp = client.get(index=index_name, id=doc_id)
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def test_index_search(client, index_name: str):
    """测试索引搜索"""
    try:
        resp = client.search(index=index_name, body={"query": {"match_all": {}}, "size": 1})
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def main():
    print("=" * 60)
    print("测试系统索引访问权限")
    print("=" * 60)
    
    reset_client()
    client = get_client()
    
    index_name = ".opendistro-alerting-config"
    workflow_id = "TeBJt5sBYd8aacU-nv8J"
    
    # 测试1: 搜索索引
    print(f"\n测试1: 搜索索引 {index_name}...")
    print("-" * 60)
    success, resp, error = test_index_search(client, index_name)
    if success:
        print(f"[OK] 可以搜索索引")
        total = resp.get('hits', {}).get('total', {})
        if isinstance(total, dict):
            total_value = total.get('value', 0)
        else:
            total_value = total
        print(f"  文档数: {total_value}")
    else:
        print(f"[X] 搜索失败: {error}")
    
    # 测试2: 尝试直接 GET 文档
    print(f"\n测试2: 尝试直接 GET 文档 (id: {workflow_id})...")
    print("-" * 60)
    success, resp, error = test_index_get(client, index_name, workflow_id)
    if success:
        print(f"[OK] 可以 GET 文档")
        print(f"  文档keys: {list(resp.get('_source', {}).keys())[:10]}")
    else:
        print(f"[X] GET 文档失败: {error}")
        if "403" in error or "forbidden" in error.lower():
            print("  [ERROR] 权限不足（403）")
        elif "404" in error:
            print("  [WARNING] 文档不存在（404），但权限可能正常")
    
    # 测试3: 尝试通过 monitor API GET
    print(f"\n测试3: 通过 monitor API GET...")
    print("-" * 60)
    try:
        resp = client.transport.perform_request(
            'GET',
            f'/_plugins/_alerting/monitors/{workflow_id}'
        )
        print(f"[OK] Monitor API GET 成功")
        print(f"  响应keys: {list(resp.keys())[:10]}")
    except Exception as e:
        error_msg = str(e)
        print(f"[X] Monitor API GET 失败: {error_msg}")
        if "indices:data/read/get" in error_msg:
            print("  [ERROR] 仍然缺少 indices:data/read/get 权限")
            print("  [INFO] 可能需要检查 OpenSearch 配置:")
            print("    - plugins.security.system_indices.permission.enabled: true")
            print("    - 或者在 Dashboards 中配置 restricted indices")
    
    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
