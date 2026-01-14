#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenSearch Security Analytics 完整测试流程

功能说明：
    完整测试 Security Analytics 流程，包括索引、规则、detector、检测和去重。
    这是最全面的 Security Analytics 测试脚本。

完整测试流程：
    1. 检查索引是否创建
    2. 检查 Sigma 规则是否导入
    3. 检查 detector 是否配置
    4. 运行 Security Analytics 检测
    5. 运行告警去重
    6. 验证 findings 索引
    7. 显示测试总结

使用场景：
    - 完整验证 Security Analytics 功能
    - 端到端测试安全检测流程
    - 验证规则导入和检测配置

环境要求：
    - OpenSearch 服务运行中
    - 已配置环境变量（OPENSEARCH_URL等）
    - Security Analytics 插件已安装
    - Sigma 规则已导入
    - Detector 已创建
    - 事件数据已存在

运行方式：
    cd backend
    uv run python scripts/opensearch/test_security_analytics_flow.py

相关脚本：
    - generate_security_test_events.py: 生成测试事件
    - clear_findings_data.py: 清除 findings 数据
"""

import sys
import io
from pathlib import Path

# Windows UTF-8 兼容
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch import (
    initialize_indices,
    run_security_analytics,
    deduplicate_findings,
    get_client,
    search,
    get_index_name,
    INDEX_PATTERNS,
)


def check_indices():
    """检查索引是否存在"""
    print("\n[步骤 1/5] 检查索引...")
    try:
        initialize_indices()
        print("[OK] 索引初始化完成")
        return True
    except Exception as e:
        print(f"[ERROR] 索引初始化失败: {e}")
        return False


def check_rules():
    """检查已导入的规则"""
    print("\n[步骤 2/5] 检查已导入的规则...")
    client = get_client()
    try:
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/rules/_search',
            body={
                "query": {"match_all": {}},
                "size": 100
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        total = response.get('hits', {}).get('total', {}).get('value', 0)
        
        print(f"[OK] 找到 {total} 个规则（显示前100个）")
        
        # 按category分组统计
        categories = {}
        for hit in hits:
            rule = hit.get('_source', {})
            category = rule.get('category', 'unknown')
            categories[category] = categories.get(category, 0) + 1
        
        print("规则分类统计:")
        for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:10]:
            print(f"  - {cat}: {count} 个")
        
        return len(hits) > 0
    except Exception as e:
        print(f"[ERROR] 检查规则失败: {e}")
        return False


def check_detectors():
    """检查detector"""
    print("\n[步骤 3/5] 检查detector...")
    client = get_client()
    try:
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/detectors/_search',
            body={
                "query": {"match_all": {}},
                "size": 10
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        total = response.get('hits', {}).get('total', {}).get('value', 0)
        
        print(f"[OK] 找到 {total} 个detector")
        
        if hits:
            for hit in hits:
                detector = hit.get('_source', {})
                detector_id = hit.get('_id')
                name = detector.get('name', 'unnamed')
                detector_type = detector.get('detector_type', 'unknown')
                enabled = detector.get('enabled', False)
                status = "[启用]" if enabled else "[禁用]"
                
                print(f"  - {name} (ID: {detector_id[:20]}...)")
                print(f"    类型: {detector_type}, 状态: {status}")
        
        return len(hits) > 0
    except Exception as e:
        print(f"[ERROR] 检查detector失败: {e}")
        return False


def test_security_analytics():
    """运行Security Analytics检测"""
    print("\n[步骤 4/5] 运行Security Analytics检测...")
    try:
        result = run_security_analytics()
        
        print(f"[OK] Security Analytics检测完成")
        print(f"  - Findings数量: {result.get('findings_count', 0)}")
        print(f"  - 转换成功: {result.get('converted_count', 0)}")
        print(f"  - 存储成功: {result.get('stored', 0)}")
        print(f"  - 失败: {result.get('failed', 0)}")
        print(f"  - 重复: {result.get('duplicated', 0)}")
        
        if result.get('stored', 0) > 0:
            print(f"\n[INFO] 成功检测到 {result.get('stored')} 个findings！")
        else:
            print(f"\n[INFO] 当前没有检测到findings（可能原因：")
            print(f"  1. Security Analytics还在扫描中（等待1-2分钟）")
            print(f"  2. 测试数据没有触发规则")
            print(f"  3. 规则配置需要调整")
        
        return result
    except Exception as e:
        print(f"[ERROR] Security Analytics检测失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_deduplication():
    """测试告警去重"""
    print("\n[步骤 5/5] 测试告警去重...")
    try:
        result = deduplicate_findings()
        
        print(f"[OK] 告警去重完成")
        print(f"  - 处理Raw Findings: {result.get('raw_count', 0)}")
        print(f"  - 生成Canonical Findings: {result.get('canonical', 0)}")
        print(f"  - 合并组数: {result.get('merged_groups', 0)}")
        
        return result
    except Exception as e:
        print(f"[ERROR] 告警去重失败: {e}")
        import traceback
        traceback.print_exc()
        return None


def verify_findings():
    """验证findings已写入索引"""
    print("\n[验证] 检查findings索引...")
    try:
        today = datetime.now()
        raw_index = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
        canonical_index = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)
        
        # 查询raw findings
        raw_findings = search(raw_index, {
            "term": {"custom.finding.providers": "security-analytics"}
        }, size=10)
        
        print(f"  - Raw Findings (Security Analytics): {len(raw_findings)} 个")
        
        # 查询canonical findings
        canonical_findings = search(canonical_index, {"match_all": {}}, size=10)
        print(f"  - Canonical Findings: {len(canonical_findings)} 个")
        
        if raw_findings:
            print(f"\n[示例] 第一个Raw Finding:")
            finding = raw_findings[0]
            print(f"  - ID: {finding.get('event', {}).get('id', 'N/A')}")
            print(f"  - 规则: {finding.get('rule', {}).get('name', 'N/A')}")
            print(f"  - 主机: {finding.get('host', {}).get('name', 'N/A')}")
            print(f"  - 时间: {finding.get('@timestamp', 'N/A')}")
        
        return True
    except Exception as e:
        print(f"[WARNING] 验证findings失败: {e}")
        return False


def main():
    print("=" * 80)
    print("Security Analytics 完整测试流程")
    print("=" * 80)
    
    # 步骤1: 检查索引
    if not check_indices():
        print("\n[ERROR] 索引检查失败，退出")
        return 1
    
    # 步骤2: 检查规则
    if not check_rules():
        print("\n[WARNING] 未找到规则，但继续测试...")
    
    # 步骤3: 检查detector
    if not check_detectors():
        print("\n[ERROR] 未找到detector，请先创建detector")
        print("  运行: uv run python opensearch/setup_security_analytics.py")
        return 1
    
    # 步骤4: 运行Security Analytics检测
    sa_result = test_security_analytics()
    
    # 步骤5: 测试告警去重
    dedup_result = test_deduplication()
    
    # 验证findings
    verify_findings()
    
    # 总结
    print("\n" + "=" * 80)
    print("测试总结")
    print("=" * 80)
    
    if sa_result:
        print(f"Security Analytics:")
        print(f"  - Findings: {sa_result.get('stored', 0)} 个")
        print(f"  - 状态: {'成功' if sa_result.get('stored', 0) > 0 else '无findings（可能正常）'}")
    
    if dedup_result:
        print(f"告警去重:")
        print(f"  - Canonical Findings: {dedup_result.get('canonical', 0)} 个")
        print(f"  - 状态: {'成功' if dedup_result.get('canonical', 0) > 0 else '无数据'}")
    
    print("\n提示:")
    print("  - 如果没有findings，可能是正常的（测试数据未触发规则）")
    print("  - Security Analytics每1分钟自动扫描，可能需要等待")
    print("  - 可以运行 generate_test_data.py 生成更多测试数据")
    
    print("=" * 80)
    return 0


if __name__ == "__main__":
    from datetime import datetime
    sys.exit(main())
