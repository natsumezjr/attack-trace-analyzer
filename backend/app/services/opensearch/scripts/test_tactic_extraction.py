#!/usr/bin/env python3
"""
测试 Tactic 提取功能

功能：
1. 运行检测获取findings
2. 检查findings中的threat.tactic信息
3. 验证tactic是否正确提取
"""

import sys
from pathlib import Path
from datetime import datetime

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from opensearch import get_client, get_index_name, INDEX_PATTERNS


def check_raw_findings_tactic():
    """检查raw findings中的tactic信息"""
    client = get_client()
    today = datetime.now()
    raw_index = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    
    if not client.indices.exists(index=raw_index):
        print("[ERROR] Raw Findings索引不存在")
        return
    
    try:
        response = client.search(
            index=raw_index,
            body={
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        
        if not hits:
            print("[WARNING] 没有找到Raw Findings")
            print("\n提示: 请先运行检测:")
            print("  cd backend/opensearch/scripts")
            print("  uv run python test_detection.py --all")
            return
        
        print(f"[OK] 找到 {len(hits)} 个Raw Findings")
        print("\n" + "=" * 100)
        print("Tactic 提取验证")
        print("=" * 100)
        
        tactic_stats = {}
        unknown_count = 0
        
        for i, hit in enumerate(hits[:10], 1):  # 只显示前10个
            finding = hit.get('_source', {})
            finding_id = finding.get('event', {}).get('id', 'N/A')
            
            threat = finding.get('threat', {})
            tactic = threat.get('tactic', {})
            tactic_id = tactic.get('id', 'N/A')
            tactic_name = tactic.get('name', 'N/A')
            
            rule_name = finding.get('rule', {}).get('name', 'N/A')
            
            print(f"\n[{i}] Finding ID: {finding_id[:30]}...")
            print(f"    规则: {rule_name}")
            print(f"    Tactic ID: {tactic_id}")
            print(f"    Tactic Name: {tactic_name}")
            
            if tactic_id == "TA0000" or tactic_name == "Unknown":
                unknown_count += 1
                print(f"    [WARNING] Tactic未提取（使用默认值）")
            else:
                print(f"    [OK] Tactic已提取")
                tactic_stats[tactic_id] = tactic_stats.get(tactic_id, 0) + 1
        
        print("\n" + "=" * 100)
        print("统计信息")
        print("=" * 100)
        
        print(f"\nTactic分布:")
        for tactic_id, count in sorted(tactic_stats.items(), key=lambda x: -x[1]):
            print(f"  {tactic_id}: {count} 个findings")
        
        print(f"\n未提取Tactic的findings: {unknown_count}/{len(hits)}")
        
        if unknown_count > 0:
            print("\n[WARNING] 部分findings的tactic未提取，可能原因：")
            print("1. 规则中没有ATT&CK标签")
            print("2. 规则查询失败")
            print("3. 规则tags格式不匹配")
        else:
            print("\n[OK] 所有findings的tactic都已正确提取！")
        
    except Exception as e:
        print(f"[ERROR] 查询失败: {e}")
        import traceback
        traceback.print_exc()


def main():
    """主函数"""
    print("=" * 100)
    print("测试 Tactic 提取功能")
    print("=" * 100)
    
    check_raw_findings_tactic()
    
    print("\n" + "=" * 100)
    print("测试完成！")
    print("=" * 100)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
