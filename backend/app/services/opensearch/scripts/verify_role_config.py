#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证角色配置

用途：检查角色配置是否正确，并显示当前用户的角色映射

使用方法：
    python verify_role_config.py [--username <用户名>] [--role-name sa_runner]
"""

import sys
import os
import argparse
import json

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client, reset_client


def get_current_user_info(client):
    """获取当前用户信息"""
    try:
        resp = client.transport.perform_request('GET', '/_plugins/_security/api/account')
        return resp, None
    except Exception as e:
        return None, str(e)


def get_role_config(client, role_name: str):
    """获取角色配置"""
    try:
        api_path = f"/_plugins/_security/api/roles/{role_name}"
        resp = client.transport.perform_request('GET', api_path)
        return resp.get(role_name, {}), None
    except Exception as e:
        return None, str(e)


def get_role_mapping(client, role_name: str):
    """获取角色映射"""
    try:
        api_path = f"/_plugins/_security/api/rolesmapping/{role_name}"
        resp = client.transport.perform_request('GET', api_path)
        return resp.get(role_name, {}), None
    except Exception as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(description='验证OpenSearch角色配置')
    parser.add_argument('--username', help='要检查的用户名（可选）')
    parser.add_argument('--role-name', default='sa_runner', help='角色名称（默认: sa_runner）')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("OpenSearch 角色配置验证")
    print("=" * 60)
    
    reset_client()
    client = get_client()
    
    # 获取当前用户信息
    print(f"\n1. 当前用户信息:")
    user_info, error = get_current_user_info(client)
    if user_info:
        print(f"   用户名: {user_info.get('user_name', 'N/A')}")
        print(f"   角色: {', '.join(user_info.get('roles', []))}")
        print(f"   后端角色: {', '.join(user_info.get('backend_roles', []))}")
    else:
        print(f"   ⚠ 无法获取用户信息: {error}")
    
    # 获取角色配置
    print(f"\n2. 角色 '{args.role_name}' 配置:")
    role_config, error = get_role_config(client, args.role_name)
    if isinstance(role_config, dict):
        print(f"   Cluster权限: {role_config.get('cluster_permissions', [])}")
        index_perms = role_config.get('index_permissions', [])
        print(f"   Index权限数量: {len(index_perms)}")
        for i, perm in enumerate(index_perms):
            print(f"     索引 {i+1}: {perm.get('index_patterns', [])}")
            print(f"       权限: {perm.get('allowed_actions', [])}")
    elif error:
        print(f"   ✗ 角色不存在或无法读取: {error}")
    else:
        print(f"   ✗ 角色不存在")
    
    # 获取角色映射
    print(f"\n3. 角色 '{args.role_name}' 映射:")
    role_mapping, error = get_role_mapping(client, args.role_name)
    if error:
        print(f"   ✗ 无法读取角色映射: {error}")
    elif isinstance(role_mapping, dict) and role_mapping:
        users = role_mapping.get('users', [])
        backend_roles = role_mapping.get('backend_roles', [])
        hosts = role_mapping.get('hosts', [])
        print(f"   用户: {users if users else '(无)'}")
        print(f"   后端角色: {backend_roles if backend_roles else '(无)'}")
        print(f"   主机: {hosts if hosts else '(无)'}")
        
        if args.username:
            if args.username in users:
                print(f"   ✓ 用户 '{args.username}' 已映射到此角色")
            else:
                print(f"   ✗ 用户 '{args.username}' 未映射到此角色")
    elif error:
        print(f"   ✗ 无法读取角色映射: {error}")
    else:
        print(f"   ✗ 角色映射不存在")
    
    print("\n" + "=" * 60)
    print("验证完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
