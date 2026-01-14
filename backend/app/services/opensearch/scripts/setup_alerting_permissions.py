#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键配置 OpenSearch Alerting 权限

用途：为程序账号配置执行 Security Analytics workflow 所需的最小权限

使用方法：
    python setup_alerting_permissions.py --username <用户名> [--role-name sa_runner]
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

from app.services.opensearch.client import get_client


# 角色配置模板（最小权限）
# 注意：根据实际索引名称更新（实际使用的是 .opendistro-alerting-config）
ROLE_CONFIG = {
    "cluster_permissions": [
        "cluster:admin/opensearch/alerting/*",  # alerting插件管理权限
        "cluster:monitor/*"  # 监控权限
    ],
    "index_permissions": [
        {
            "index_patterns": [
                # 实际使用的索引（根据find_alerting_indices.py的输出）
                ".opendistro-alerting-config",  # 实际存储monitor配置的索引
                ".opendistro-alerting-config*",
                ".opendistro-alerting-alerts",
                ".opendistro-alerting-alerts*",
                ".opendistro-alerting-alert-history-*",
                ".opendistro-alerting-*",  # 匹配所有opendistro alerting索引
                # 兼容opensearch格式（如果存在）
                ".opensearch-alerting-config",
                ".opensearch-alerting-config*",
                ".opensearch-alerting-config-lock",
                ".opensearch-alerting-*",
                # 业务索引
                "ecs-events-*"
            ],
            "allowed_actions": [
                "read",
                "search",
                "indices:data/read/get",
                "indices:data/read/search",
                "indices:data/read/get[s]",  # 明确指定get操作
                "indices:data/read/search[s]"  # 明确指定search操作
            ]
        }
    ]
}


def check_security_api_available(client):
    """检查Security API是否可用"""
    try:
        resp = client.transport.perform_request('GET', '/_plugins/_security/api/roles')
        return True
    except Exception as e:
        error_msg = str(e)
        if '404' in error_msg or 'not found' in error_msg.lower():
            return False, "Security REST API不可用（404），可能需要通过Dashboards UI配置"
        elif '403' in error_msg or 'forbidden' in error_msg.lower():
            return False, "Security REST API权限不足（403），请使用admin账号"
        else:
            return False, f"Security REST API检查失败: {error_msg}"


def create_or_update_role(client, role_name: str, role_config: dict):
    """创建或更新角色"""
    try:
        api_path = f"/_plugins/_security/api/roles/{role_name}"
        resp = client.transport.perform_request('PUT', api_path, body=role_config)
        return True, resp
    except Exception as e:
        return False, str(e)


def map_user_to_role(client, role_name: str, username: str):
    """将用户映射到角色"""
    try:
        # 先获取现有的role mapping
        api_path = f"/_plugins/_security/api/rolesmapping/{role_name}"
        try:
            existing = client.transport.perform_request('GET', api_path)
            users = existing.get(role_name, {}).get('users', [])
            backend_roles = existing.get(role_name, {}).get('backend_roles', [])
            hosts = existing.get(role_name, {}).get('hosts', [])
        except Exception:
            # 如果不存在，创建新的
            users = []
            backend_roles = []
            hosts = []
        
        # 添加用户（如果不存在）
        if username not in users:
            users.append(username)
        
        # 更新role mapping
        mapping_config = {
            "users": users,
            "backend_roles": backend_roles,
            "hosts": hosts
        }
        
        resp = client.transport.perform_request('PUT', api_path, body=mapping_config)
        return True, resp
    except Exception as e:
        return False, str(e)


def test_permissions(client, workflow_id: str):
    """测试权限是否配置成功"""
    print(f"\n测试权限配置...")
    
    # 测试1: GET monitor配置
    try:
        monitor_get_path = f"/_plugins/_alerting/monitors/{workflow_id}"
        resp = client.transport.perform_request('GET', monitor_get_path)
        print(f"✓ GET monitor配置成功")
        return True
    except Exception as e:
        error_msg = str(e)
        if '500' in error_msg and 'indices:data/read/get' in error_msg:
            print(f"✗ GET monitor配置失败：权限不足")
            print(f"  错误: {error_msg}")
            return False
        else:
            print(f"⚠ GET monitor配置失败：{error_msg}")
            return False


def main():
    parser = argparse.ArgumentParser(description='配置OpenSearch Alerting权限')
    parser.add_argument('--username', required=True, help='要配置权限的用户名')
    parser.add_argument('--role-name', default='sa_runner', help='角色名称（默认: sa_runner）')
    parser.add_argument('--workflow-id', help='workflow ID（用于测试权限，可选）')
    parser.add_argument('--dry-run', action='store_true', help='只检查，不实际配置')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("OpenSearch Alerting 权限配置工具")
    print("=" * 60)
    
    client = get_client()
    
    # 步骤1: 检查Security API是否可用
    print(f"\n步骤1: 检查Security API可用性...")
    api_check = check_security_api_available(client)
    if isinstance(api_check, tuple) and not api_check[0]:
        print(f"✗ {api_check[1]}")
        print(f"\n建议：")
        print(f"  1. 使用admin账号运行此脚本")
        print(f"  2. 或通过OpenSearch Dashboards UI手动配置权限")
        print(f"  3. 或使用securityadmin工具（如果可用）")
        return 1
    
    print(f"✓ Security API可用")
    
    if args.dry_run:
        print(f"\n[DRY RUN] 将执行以下操作：")
        print(f"  1. 创建/更新角色: {args.role_name}")
        print(f"  2. 将用户 {args.username} 映射到角色 {args.role_name}")
        print(f"\n角色配置:")
        print(json.dumps(ROLE_CONFIG, indent=2, ensure_ascii=False))
        return 0
    
    # 步骤2: 创建/更新角色
    print(f"\n步骤2: 创建/更新角色 '{args.role_name}'...")
    success, result = create_or_update_role(client, args.role_name, ROLE_CONFIG)
    if success:
        print(f"✓ 角色 '{args.role_name}' 配置成功")
    else:
        print(f"✗ 角色配置失败: {result}")
        return 1
    
    # 步骤3: 映射用户到角色
    print(f"\n步骤3: 将用户 '{args.username}' 映射到角色 '{args.role_name}'...")
    success, result = map_user_to_role(client, args.role_name, args.username)
    if success:
        print(f"✓ 用户映射成功")
    else:
        print(f"✗ 用户映射失败: {result}")
        return 1
    
    # 步骤4: 测试权限（如果提供了workflow_id）
    if args.workflow_id:
        print(f"\n步骤4: 测试权限配置...")
        # 需要重新创建client（使用新权限）
        print(f"⚠ 注意：需要重新连接OpenSearch以应用新权限")
        print(f"   请重新运行测试脚本验证权限")
    else:
        print(f"\n步骤4: 权限配置完成")
        print(f"\n下一步：")
        print(f"  1. 重新连接OpenSearch以应用新权限")
        print(f"     方法1: 重新运行脚本（会自动重置连接）")
        print(f"     方法2: 重启Python进程")
        print(f"     方法3: 在代码中调用 reset_client()")
        print(f"  2. 运行测试脚本验证权限:")
        print(f"     python check_alerting_permissions.py")
        print(f"     python test_step7_security_analytics.py --trigger-scan")
    
    print("\n" + "=" * 60)
    print("配置完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
