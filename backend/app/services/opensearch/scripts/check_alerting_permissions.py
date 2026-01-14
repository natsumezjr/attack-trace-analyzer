#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查 OpenSearch Alerting 权限

用途：检查当前用户是否具备执行 Security Analytics workflow 的权限

使用方法：
    python check_alerting_permissions.py [--workflow-id <workflow_id>]
"""

import sys
import os
import argparse

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client, reset_client
from app.services.opensearch.analysis import _get_workflow_id_for_detector, _get_detector_id


def check_monitor_read_permission(client, workflow_id: str):
    """检查是否有读取monitor配置的权限"""
    try:
        monitor_get_path = f"/_plugins/_alerting/monitors/{workflow_id}"
        resp = client.transport.perform_request('GET', monitor_get_path)
        # 检查响应是否包含monitor数据
        if resp and ('monitor' in resp or 'id' in resp or 'name' in resp):
            return True, "✓ 有读取monitor配置的权限"
        else:
            return False, "✗ 读取成功但响应格式异常"
    except Exception as e:
        error_msg = str(e)
        if '500' in error_msg and 'indices:data/read/get' in error_msg:
            return False, "✗ 缺少读取monitor配置的权限（indices:data/read/get）"
        elif '403' in error_msg or 'forbidden' in error_msg.lower():
            return False, "✗ 权限被拒绝（403 Forbidden）"
        elif 'security' in error_msg.lower() or 'authorization' in error_msg.lower():
            return False, f"✗ 权限不足: {error_msg}"
        else:
            return False, f"✗ 读取失败: {error_msg}"


def check_monitor_execute_permission(client, workflow_id: str):
    """检查是否有执行monitor的权限"""
    try:
        execute_path = f"/_plugins/_alerting/monitors/{workflow_id}/_execute"
        resp = client.transport.perform_request('POST', execute_path, body={})
        return True, "✓ 有执行monitor的权限"
    except Exception as e:
        error_msg = str(e)
        if '500' in error_msg and 'indices:data/read/get' in error_msg:
            return False, "✗ 缺少执行权限（可能是读取系统索引权限不足）"
        elif '403' in error_msg or 'forbidden' in error_msg.lower():
            return False, "✗ 执行权限被拒绝（403 Forbidden）"
        else:
            return False, f"✗ 执行失败: {error_msg}"


def main():
    parser = argparse.ArgumentParser(description='检查OpenSearch Alerting权限')
    parser.add_argument('--workflow-id', help='workflow ID（如果不提供，会自动查找）')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("OpenSearch Alerting 权限检查")
    print("=" * 60)
    
    # 重置客户端以确保使用最新权限
    print(f"\n重置OpenSearch客户端连接以应用最新权限...")
    reset_client()
    
    client = get_client()
    
    # 获取workflow_id
    if args.workflow_id:
        workflow_id = args.workflow_id
        print(f"\n使用指定的workflow_id: {workflow_id}")
    else:
        print(f"\n自动查找workflow...")
        detector_id = _get_detector_id(client)
        if not detector_id:
            print("✗ 未找到detector")
            return 1
        
        workflow_id = _get_workflow_id_for_detector(client, detector_id)
        if not workflow_id:
            print("✗ 未找到workflow")
            return 1
        
        print(f"✓ 找到workflow: {workflow_id}")
    
    # 检查权限
    print(f"\n检查权限...")
    
    # 检查1: 读取monitor配置权限
    print(f"\n1. 检查读取monitor配置权限...")
    success, message = check_monitor_read_permission(client, workflow_id)
    print(f"   {message}")
    
    if not success:
        print(f"\n   建议：")
        print(f"   - 运行 setup_alerting_permissions.py 配置权限")
        print(f"   - 或通过Dashboards UI将用户映射到alerting_full_access角色")
        return 1
    
    # 检查2: 执行monitor权限
    print(f"\n2. 检查执行monitor权限...")
    success, message = check_monitor_execute_permission(client, workflow_id)
    print(f"   {message}")
    
    if not success:
        print(f"\n   建议：")
        print(f"   - 运行 setup_alerting_permissions.py 配置权限")
        print(f"   - 或通过Dashboards UI将用户映射到alerting_full_access角色")
        return 1
    
    print(f"\n" + "=" * 60)
    print("✓ 所有权限检查通过")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
