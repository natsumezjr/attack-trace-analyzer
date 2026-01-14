#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
查找 Alerting 系统索引

用途：查找实际的 alerting 系统索引名称，用于配置权限

使用方法：
    python find_alerting_indices.py
"""

import sys
import os

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client, reset_client


def find_alerting_indices(client):
    """查找所有alerting相关的索引"""
    try:
        # 查找所有以 alerting 开头的索引
        indices = client.indices.get_alias(index="*alerting*")
        return list(indices.keys())
    except Exception as e:
        print(f"查找索引失败: {e}")
        return []


def find_opensearch_indices(client):
    """查找所有以 .opensearch 开头的索引"""
    try:
        indices = client.indices.get_alias(index=".opensearch*")
        return list(indices.keys())
    except Exception as e:
        print(f"查找索引失败: {e}")
        return []


def main():
    print("=" * 60)
    print("查找 Alerting 系统索引")
    print("=" * 60)
    
    reset_client()
    client = get_client()
    
    # 查找alerting相关索引
    print(f"\n1. 查找 *alerting* 索引:")
    alerting_indices = find_alerting_indices(client)
    if alerting_indices:
        for idx in alerting_indices:
            print(f"   - {idx}")
    else:
        print("   (未找到)")
    
    # 查找.opensearch开头的索引
    print(f"\n2. 查找 .opensearch* 索引:")
    opensearch_indices = find_opensearch_indices(client)
    if opensearch_indices:
        for idx in opensearch_indices:
            print(f"   - {idx}")
    else:
        print("   (未找到)")
    
    # 查找所有系统索引
    print(f"\n3. 查找所有系统索引（以 . 开头）:")
    try:
        all_indices = client.indices.get_alias(index=".*")
        system_indices = [idx for idx in all_indices.keys() if 'alerting' in idx.lower() or 'monitor' in idx.lower()]
        if system_indices:
            for idx in system_indices:
                print(f"   - {idx}")
        else:
            print("   (未找到alerting/monitor相关索引)")
    except Exception as e:
        print(f"   查找失败: {e}")
    
    print("\n" + "=" * 60)
    print("查找完成")
    print("=" * 60)
    print("\n建议：")
    print("  1. 将找到的索引名称添加到角色配置的 index_patterns 中")
    print("  2. 重新运行 setup_alerting_permissions.py 更新权限")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
