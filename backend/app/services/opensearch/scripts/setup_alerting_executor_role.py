#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置 Alerting Executor 角色（解决 restricted indices 权限问题）

用途：
1. 创建/更新 alerting_executor 角色（允许访问 .opendistro-alerting-* restricted indices）
2. 将 admin 用户映射到这个角色
3. 验证配置是否生效

使用方法：
    python setup_alerting_executor_role.py
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


def get_opensearch_config():
    """获取 OpenSearch 配置（用于构建 API URL）"""
    node_url = os.getenv("OPENSEARCH_NODE", "https://localhost:9200")
    username = os.getenv("OPENSEARCH_USERNAME", "admin")
    password = os.getenv("OPENSEARCH_PASSWORD", "OpenSearch@2024!Dev")
    
    from urllib.parse import urlparse
    parsed = urlparse(node_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 9200
    scheme = parsed.scheme or "https"
    
    base_url = f"{scheme}://{host}:{port}"
    
    return base_url, username, password


def create_or_update_role(client, role_name: str, role_config: dict):
    """创建或更新角色"""
    try:
        resp = client.transport.perform_request(
            'PUT',
            f'/_plugins/_security/api/roles/{role_name}',
            body=role_config
        )
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def create_or_update_role_mapping(client, role_name: str, users: list, backend_roles: list = None, hosts: list = None):
    """创建或更新角色映射"""
    try:
        mapping = {
            "users": users,
            "backend_roles": backend_roles or [],
            "hosts": hosts or []
        }
        resp = client.transport.perform_request(
            'PUT',
            f'/_plugins/_security/api/rolesmapping/{role_name}',
            body=mapping
        )
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def get_authinfo(client):
    """获取当前用户信息"""
    try:
        resp = client.transport.perform_request('GET', '/_plugins/_security/authinfo')
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def test_monitor_get(client, workflow_id: str):
    """测试 GET monitor API"""
    try:
        resp = client.transport.perform_request(
            'GET',
            f'/_plugins/_alerting/monitors/{workflow_id}'
        )
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def test_monitor_execute(client, workflow_id: str):
    """测试 POST monitor execute API"""
    try:
        resp = client.transport.perform_request(
            'POST',
            f'/_plugins/_alerting/monitors/{workflow_id}/_execute',
            body={}
        )
        return True, resp, None
    except Exception as e:
        return False, None, str(e)


def main():
    parser = argparse.ArgumentParser(description='配置 Alerting Executor 角色')
    parser.add_argument('--workflow-id', default='TeBJt5sBYd8aacU-nv8J', help='用于测试的 workflow ID')
    parser.add_argument('--user', default='admin', help='要映射的用户名（默认: admin）')
    parser.add_argument('--dry-run', action='store_true', help='仅显示配置，不实际执行')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("配置 Alerting Executor 角色")
    print("=" * 60)
    
    # 获取配置
    base_url, username, password = get_opensearch_config()
    print(f"\nOpenSearch 配置:")
    print(f"  URL: {base_url}")
    print(f"  用户名: {username}")
    print(f"  密码: {'*' * len(password)}")
    
    # 角色配置
    # 注意：访问系统索引需要使用 system:admin/system_index 权限
    role_name = "alerting_executor"
    role_config = {
        "cluster_permissions": [
            "cluster:admin/opensearch/alerting/*",
            "cluster:monitor/*"
        ],
        "index_permissions": [
            {
                "index_patterns": [".opendistro-alerting-*"],
                # 关键：使用 system:admin/system_index 权限访问系统索引
                "allowed_actions": [
                    "system:admin/system_index",  # 允许访问系统索引
                    "read",
                    "search",
                    "indices:data/read/get",
                    "indices:data/read/search"
                ]
            },
            {
                "index_patterns": ["ecs-events-*"],
                "allowed_actions": ["read", "search", "indices:data/read/get", "indices:data/read/search"]
            }
        ]
    }
    
    print(f"\n角色配置 ({role_name}):")
    print(json.dumps(role_config, indent=2, ensure_ascii=False))
    
    if args.dry_run:
        print("\n[DRY-RUN] 仅显示配置，不实际执行")
        return 0
    
    reset_client()
    client = get_client()
    
    # 步骤1: 创建/更新角色
    print(f"\n步骤 1: 创建/更新角色 '{role_name}'...")
    print("-" * 60)
    success, resp, error = create_or_update_role(client, role_name, role_config)
    if success:
        print(f"[OK] 角色创建/更新成功")
        if resp:
            print(f"响应: {json.dumps(resp, indent=2, ensure_ascii=False)}")
    else:
        print(f"[X] 角色创建/更新失败: {error}")
        if "404" in error:
            print("[ERROR] Security API 可能未启用，或路径不正确")
        elif "403" in error:
            print("[ERROR] 当前用户没有权限调用 Security API")
        elif "500" in error:
            print("[ERROR] 可能是反向代理/证书/认证方式问题")
        return 1
    
    # 步骤2: 创建/更新角色映射
    print(f"\n步骤 2: 将用户 '{args.user}' 映射到角色 '{role_name}'...")
    print("-" * 60)
    success, resp, error = create_or_update_role_mapping(client, role_name, [args.user])
    if success:
        print(f"[OK] 角色映射创建/更新成功")
        if resp:
            print(f"响应: {json.dumps(resp, indent=2, ensure_ascii=False)}")
    else:
        print(f"[X] 角色映射创建/更新失败: {error}")
        return 1
    
    # 步骤3: 重置客户端连接（确保使用新权限）
    print(f"\n步骤 3: 重置客户端连接（应用新权限）...")
    print("-" * 60)
    reset_client()
    client = get_client()
    print("[OK] 客户端连接已重置")
    
    # 步骤4: 验证权限
    print(f"\n步骤 4: 验证权限配置...")
    print("-" * 60)
    success, authinfo, error = get_authinfo(client)
    if success:
        user_roles = authinfo.get('roles', [])
        print(f"[OK] 当前用户角色: {user_roles}")
        if role_name in user_roles:
            print(f"[OK] 角色 '{role_name}' 已生效")
        else:
            print(f"[WARNING] 角色 '{role_name}' 未在角色列表中，但可能通过 all_access 生效")
    else:
        print(f"[WARNING] 无法获取用户信息: {error}")
    
    # 步骤5: 测试 monitor API
    print(f"\n步骤 5: 测试 monitor API...")
    print("-" * 60)
    
    # 5.1: 测试 GET monitor
    print(f"\n5.1 测试 GET monitor (workflow_id: {args.workflow_id})...")
    success, resp, error = test_monitor_get(client, args.workflow_id)
    if success:
        print(f"[OK] GET monitor API 成功")
        print(f"响应keys: {list(resp.keys())[:10]}")
    else:
        print(f"[X] GET monitor API 失败: {error}")
        if "indices:data/read/get" in error:
            print("[ERROR] 仍然缺少 indices:data/read/get 权限")
            print("[ERROR] 可能需要检查 allow_restricted_indices 配置")
    
    # 5.2: 测试 POST execute
    print(f"\n5.2 测试 POST monitor execute...")
    success, resp, error = test_monitor_execute(client, args.workflow_id)
    if success:
        print(f"[OK] POST monitor execute API 成功")
        print(f"响应: {json.dumps(resp, indent=2, ensure_ascii=False)}")
    else:
        print(f"[X] POST monitor execute API 失败: {error}")
        if "indices:data/read/get" in error:
            print("[ERROR] 仍然缺少 indices:data/read/get 权限")
    
    print("\n" + "=" * 60)
    print("配置完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
