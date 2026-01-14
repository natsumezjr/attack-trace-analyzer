#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 8：手动触发 Workflow 测试"""
import sys
import os
import time

# 添加项目路径：从 scripts/ 目录向上找到 backend/ 目录
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

# 将 backend/ 目录添加到路径，这样就可以导入 app.services.opensearch
sys.path.insert(0, backend_dir)

from app.services.opensearch.analysis import _get_detector_id, _get_workflow_id_for_detector, _execute_workflow_manually, _get_latest_findings_timestamp
from app.services.opensearch.client import get_client, reset_client
import json

def check_current_user_info(client):
    """检查并输出当前用户信息"""
    try:
        # 使用 authinfo API 获取当前用户信息
        authinfo = client.transport.perform_request('GET', '/_plugins/_security/authinfo')
        
        user_name = authinfo.get('user_name', 'N/A')
        backend_roles = authinfo.get('backend_roles', [])
        roles = authinfo.get('roles', [])
        
        print("\n当前 OpenSearch 用户信息:")
        print("-" * 60)
        print(f"  用户名: {user_name}")
        print(f"  Backend roles: {backend_roles}")
        print(f"  Roles: {roles}")
        
        # 检查是否有 admin 权限
        has_admin_backend_role = 'admin' in backend_roles
        has_all_access_role = 'all_access' in roles
        
        if has_admin_backend_role:
            print("  [OK] 有 backend_role: admin")
        else:
            print("  [X] 没有 backend_role: admin")
        
        if has_all_access_role:
            print("  [OK] 有 role: all_access")
        else:
            print("  [X] 没有 role: all_access")
        
        if not has_admin_backend_role and not has_all_access_role:
            print("  [WARNING] 当前用户不是 admin，可能没有最高权限！")
        
        print("-" * 60)
        return True
    except Exception as e:
        print(f"\n[WARNING] 无法获取当前用户信息: {e}")
        print("-" * 60)
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("步骤 8：手动触发 Workflow 测试")
    print("=" * 60)
    
    # 重置客户端连接（确保使用最新权限）
    reset_client()
    client = get_client()
    
    # 先输出当前用户信息
    check_current_user_info(client)
    
    # 获取 detector ID
    print("\n获取 Detector ID...")
    detector_id = _get_detector_id(client)
    if not detector_id:
        print("[X] 未找到 detector ID")
        sys.exit(1)
    print(f"[OK] Detector ID: {detector_id}")
    
    # 获取 workflow ID
    print("\n获取 Workflow ID...")
    workflow_id = _get_workflow_id_for_detector(client, detector_id)
    
    if not workflow_id:
        print("[WARNING] 未找到 workflow ID")
        print("\n说明:")
        print("  Security Analytics detector 存在，但没有找到对应的workflow")
        print("  这可能是因为:")
        print("    1. Detector创建时没有自动创建workflow")
        print("    2. 可以使用 run_security_analytics(trigger_scan=True) 触发扫描")
        print("      它会fallback到临时改schedule的方式")
        print("\n跳过workflow手动触发测试，直接测试完整流程...")
        print("=" * 60)
        print("[OK] 步骤8跳过（workflow不存在，但可以使用schedule方式触发）")
        print("=" * 60)
        sys.exit(0)  # 退出码0表示跳过，不是失败
    else:
        print(f"[OK] Workflow ID: {workflow_id}")
    
    # 获取触发前的findings数量
    print("\n查询触发前的findings数量...")
    before_timestamp_ms, before_count = _get_latest_findings_timestamp(client, detector_id)
    print(f"  当前 Findings: {before_count} 个")
    if before_timestamp_ms > 0:
        print(f"  最新 Finding 时间戳: {before_timestamp_ms}")
    
    # 手动触发 workflow
    print("\n手动触发 workflow...")
    success = _execute_workflow_manually(client, workflow_id)
    
    if not success:
        print("[X] Workflow 触发失败")
        sys.exit(1)
    
    print("[OK] Workflow 触发成功")
    print("\n等待5秒让扫描完成...")
    time.sleep(5)
    
    # 查询触发后的findings数量
    print("\n查询触发后的findings数量...")
    after_timestamp_ms, after_count = _get_latest_findings_timestamp(client, detector_id)
    print(f"  当前 Findings: {after_count} 个")
    if after_timestamp_ms > 0:
        print(f"  最新 Finding 时间戳: {after_timestamp_ms}")
    
    print("\n" + "=" * 60)
    if after_count >= before_count:
        if after_timestamp_ms > before_timestamp_ms:
            print("[OK] Workflow 手动触发测试通过")
            print(f"  发现新findings（时间戳更新: {before_timestamp_ms} -> {after_timestamp_ms}）")
        else:
            print("[WARNING] Workflow 触发成功，但可能没有产生新findings")
            print("  可能原因: 数据没有变化，或规则不匹配新数据")
    else:
        print("[WARNING] Findings数量减少（可能是数据清理或索引刷新）")
    print("=" * 60)
