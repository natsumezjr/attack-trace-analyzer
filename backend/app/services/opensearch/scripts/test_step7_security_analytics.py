#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 7：Security Analytics 检测测试"""
import sys
import os

# 添加项目路径：从 scripts/ 目录向上找到 backend/ 目录
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

# 将 backend/ 目录添加到路径，这样就可以导入 app.services.opensearch
sys.path.insert(0, backend_dir)

from app.services.opensearch.analysis import run_security_analytics
from app.services.opensearch.client import reset_client

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Analytics 检测测试')
    parser.add_argument('--trigger-scan', action='store_true', 
                       help='是否触发新扫描（默认False，只查询已有findings）')
    args = parser.parse_args()
    
    print("=" * 60)
    print("步骤 7：Security Analytics 检测测试")
    print("=" * 60)
    
    # 重置客户端连接（确保使用最新权限）
    # 注意：如果权限刚配置，需要重置连接才能生效
    reset_client()
    
    if args.trigger_scan:  # argparse会自动将--trigger-scan转换为trigger_scan属性
        print("\n触发新扫描并查询findings...")
        result = run_security_analytics(trigger_scan=True, force_scan=True)
    else:
        print("\n查询已有findings（不触发新扫描）...")
        print("提示: 如需触发新扫描，使用 --trigger-scan 参数")
        result = run_security_analytics(trigger_scan=False)
    
    print("\n检测结果:")
    print(f"  成功: {result['success']}")
    print(f"  Findings总数: {result['findings_count']}")
    print(f"  新Findings: {result.get('new_findings_count', 0)}")
    print(f"  存储成功: {result['stored']}")
    print(f"  重复跳过: {result.get('duplicated', 0)}")
    print(f"  扫描请求: {result.get('scan_requested', False)}")
    print(f"  扫描完成: {result.get('scan_completed', False)}")
    print(f"  等待时间: {result.get('scan_wait_ms', 0)}ms")
    print(f"  来源: {result['source']}")
    
    print("\n" + "=" * 60)
    if result['findings_count'] > 0:
        print("✓ 检测功能正常，发现 findings")
    elif result['success']:
        print("⚠ 检测功能正常，但没有 findings")
        print("\n可能原因:")
        print("  1. 没有测试数据在 ecs-events-* 索引中")
        print("  2. Security Analytics detector 未配置或未启用")
        print("  3. 规则查询条件不匹配数据")
        print("\n提示: 如果需要触发新扫描，可以运行:")
        print("  run_security_analytics(force_scan=True)")
    else:
        print("✗ 检测功能异常")
        print(f"  错误信息: {result.get('message', '未知错误')}")
    print("=" * 60)
