#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查当前 OpenSearch 客户端的实际身份

用途：确认代码实际使用的用户身份，以及该用户的 roles 和 backend_roles

使用方法：
    python check_current_user_identity.py
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


def check_authinfo(client):
    """检查当前用户的身份信息"""
    try:
        # 调用 OpenSearch Security 的 authinfo API
        resp = client.transport.perform_request('GET', '/_plugins/_security/authinfo')
        return resp, None
    except Exception as e:
        return None, str(e)


def check_current_user(client):
    """检查当前用户信息（通过 whoami API）"""
    try:
        resp = client.transport.perform_request('GET', '/_plugins/_security/api/account')
        return resp, None
    except Exception as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(description='检查当前 OpenSearch 客户端身份')
    parser.add_argument('--reset', action='store_true', help='重置客户端连接（清除缓存）')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("检查当前 OpenSearch 客户端身份")
    print("=" * 60)
    
    if args.reset:
        reset_client()
        print("\n[OK] 已重置客户端连接")
    
    client = get_client()
    
    # 方法1: 使用 authinfo API（推荐）
    print("\n1. 使用 authinfo API 检查身份:")
    print("-" * 60)
    authinfo, error = check_authinfo(client)
    if authinfo:
        print("[OK] authinfo API 调用成功")
        print("\n当前身份信息:")
        print(json.dumps(authinfo, indent=2, ensure_ascii=False))
        
        # 提取关键信息
        user_name = authinfo.get('user_name', 'N/A')
        backend_roles = authinfo.get('backend_roles', [])
        roles = authinfo.get('roles', [])
        
        print("\n关键信息:")
        print(f"  用户名: {user_name}")
        print(f"  Backend roles: {backend_roles}")
        print(f"  Roles: {roles}")
        
        # 检查是否有 admin 权限
        has_admin_backend_role = 'admin' in backend_roles
        has_all_access_role = 'all_access' in roles
        
        print("\n权限检查:")
        if has_admin_backend_role:
            print("  [OK] 有 backend_role: admin")
        else:
            print("  [X] 没有 backend_role: admin")
        
        if has_all_access_role:
            print("  [OK] 有 role: all_access")
        else:
            print("  [X] 没有 role: all_access")
        
        if not has_admin_backend_role and not has_all_access_role:
            print("\n[WARNING] 警告：当前用户不是 admin，可能没有最高权限！")
            print("   这解释了为什么会有权限错误。")
            print("   需要为当前用户配置正确的权限，或使用 admin 用户。")
    else:
        print(f"[X] authinfo API 调用失败: {error}")
    
    # 方法2: 使用 account API（备用）
    print("\n2. 使用 account API 检查身份:")
    print("-" * 60)
    account_info, error = check_current_user(client)
    if account_info:
        print("[OK] account API 调用成功")
        print("\n账户信息:")
        print(json.dumps(account_info, indent=2, ensure_ascii=False))
    else:
        print(f"[X] account API 调用失败: {error}")
    
    # 方法3: 尝试获取当前用户信息（通过 transport）
    print("\n3. 尝试其他方式获取用户信息:")
    print("-" * 60)
    try:
        # 尝试获取集群信息（会显示当前用户）
        cluster_info = client.info()
        print("✓ 可以获取集群信息")
        print(f"  集群名称: {cluster_info.get('cluster_name', 'N/A')}")
        print(f"  OpenSearch 版本: {cluster_info.get('version', {}).get('number', 'N/A')}")
    except Exception as e:
        print(f"[X] 获取集群信息失败: {e}")
    
    print("\n" + "=" * 60)
    print("检查完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
