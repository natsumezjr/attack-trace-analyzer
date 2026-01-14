#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查 all_access 角色的实际配置

用途：查看 all_access 角色是否真的包含对 alerting 系统索引的完整权限

使用方法：
    python check_all_access_role.py
"""

import sys
import os
import json
import argparse

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client, reset_client


def get_role_config(client, role_name: str):
    """获取角色的配置"""
    try:
        resp = client.transport.perform_request('GET', f'/_plugins/_security/api/roles/{role_name}')
        return resp, None
    except Exception as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(description='检查 all_access 角色配置')
    parser.add_argument('--reset', action='store_true', help='重置客户端连接')
    parser.add_argument('--role', default='all_access', help='要检查的角色名称（默认: all_access）')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print(f"检查角色配置: {args.role}")
    print("=" * 60)
    
    if args.reset:
        reset_client()
        print("\n[OK] 已重置客户端连接")
    
    client = get_client()
    
    # 获取角色配置
    print(f"\n1. 获取角色配置:")
    print("-" * 60)
    role_config, error = get_role_config(client, args.role)
    if role_config:
        print(f"[OK] 成功获取角色配置")
        print("\n角色配置详情:")
        print(json.dumps(role_config, indent=2, ensure_ascii=False))
        
        # 分析权限（注意：role_config 可能是一个字典，key 是角色名）
        if isinstance(role_config, dict) and args.role in role_config:
            role_data = role_config[args.role]
        else:
            role_data = role_config
        
        cluster_permissions = role_data.get('cluster_permissions', [])
        index_permissions = role_data.get('index_permissions', [])
        
        print("\n权限分析:")
        print(f"  集群权限数量: {len(cluster_permissions)}")
        if cluster_permissions:
            print(f"  集群权限列表:")
            for perm in cluster_permissions[:10]:
                print(f"    - {perm}")
            if len(cluster_permissions) > 10:
                print(f"    ... 还有 {len(cluster_permissions) - 10} 个权限")
        
        print(f"\n  索引权限数量: {len(index_permissions)}")
        if index_permissions:
            print(f"  索引权限详情:")
            for idx_perm in index_permissions:
                patterns = idx_perm.get('index_patterns', [])
                actions = idx_perm.get('allowed_actions', [])
                print(f"    索引模式: {patterns}")
                print(f"    允许的操作: {actions}")
                print()
        
        # 检查是否包含 alerting 相关权限
        print("\nAlerting 相关权限检查:")
        has_alerting_cluster_perm = any('alerting' in str(p).lower() for p in cluster_permissions)
        has_alerting_index_perm = any(
            any('alerting' in str(p).lower() for p in idx_perm.get('index_patterns', []))
            for idx_perm in index_permissions
        )
        
        if has_alerting_cluster_perm:
            print("  [OK] 有 alerting 相关的集群权限")
        else:
            print("  [X] 没有 alerting 相关的集群权限")
        
        if has_alerting_index_perm:
            print("  [OK] 有 alerting 相关的索引权限")
        else:
            print("  [X] 没有 alerting 相关的索引权限")
        
        # 检查是否有通配符权限
        has_wildcard_cluster = '*' in cluster_permissions or any('*' in str(p) for p in cluster_permissions)
        has_wildcard_index = any(
            '*' in idx_perm.get('index_patterns', []) or any('*' in str(p) for p in idx_perm.get('index_patterns', []))
            for idx_perm in index_permissions
        )
        has_wildcard_actions = any(
            '*' in idx_perm.get('allowed_actions', []) or any('*' in str(a) for a in idx_perm.get('allowed_actions', []))
            for idx_perm in index_permissions
        )
        
        print("\n通配符权限检查:")
        if has_wildcard_cluster:
            print("  [OK] 有通配符集群权限（cluster_permissions: [\"*\"]）")
            print("       这意味着拥有所有集群权限，包括 alerting 相关权限")
        else:
            print("  [X] 没有通配符集群权限")
        
        if has_wildcard_index:
            print("  [OK] 有通配符索引模式（index_patterns: [\"*\"]）")
            print("       这意味着可以访问所有索引，包括 alerting 系统索引")
        else:
            print("  [X] 没有通配符索引模式")
        
        if has_wildcard_actions:
            print("  [OK] 有通配符操作权限（allowed_actions: [\"*\"]）")
            print("       这意味着拥有所有索引操作权限，包括 indices:data/read/get")
        else:
            print("  [X] 没有通配符操作权限")
        
        # 检查是否有 indices:data/read/get 权限
        has_get_action = any(
            'indices:data/read/get' in str(a) or 'get' in str(a).lower()
            for idx_perm in index_permissions
            for a in idx_perm.get('allowed_actions', [])
        )
        
        print("\n索引读取权限检查:")
        if has_get_action:
            print("  [OK] 有 indices:data/read/get 权限")
        else:
            print("  [X] 没有 indices:data/read/get 权限")
            print("  [WARNING] 这可能是权限错误的根本原因！")
    else:
        print(f"[X] 获取角色配置失败: {error}")
    
    print("\n" + "=" * 60)
    print("检查完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
