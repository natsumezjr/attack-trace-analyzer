#!/usr/bin/env python3
"""
展示 Findings 链：Event -> Raw Finding -> Canonical Finding

功能：
1. 查询raw-findings索引中的findings
2. 查询canonical-findings索引中的canonical findings
3. 展示它们之间的关联关系
4. 显示哪些原始findings被合并成了哪个canonical finding
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS


def get_raw_findings():
    """获取所有raw findings"""
    client = get_client()
    today = datetime.now()
    raw_index = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    
    if not client.indices.exists(index=raw_index):
        return []
    
    try:
        response = client.search(
            index=raw_index,
            body={
                "size": 1000,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        findings = []
        for hit in hits:
            finding = hit.get('_source', {})
            finding['_id'] = hit.get('_id')
            findings.append(finding)
        return findings
    except Exception as e:
        print(f"❌ 查询raw findings失败: {e}")
        return []


def get_canonical_findings():
    """获取所有canonical findings"""
    client = get_client()
    today = datetime.now()
    canonical_index = get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], today)
    
    if not client.indices.exists(index=canonical_index):
        return []
    
    try:
        response = client.search(
            index=canonical_index,
            body={
                "size": 1000,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        hits = response.get('hits', {}).get('hits', [])
        findings = []
        for hit in hits:
            finding = hit.get('_source', {})
            finding['_id'] = hit.get('_id')
            findings.append(finding)
        return findings
    except Exception as e:
        print(f"❌ 查询canonical findings失败: {e}")
        return []


def get_related_events(finding):
    """从finding中提取相关事件ID"""
    event_ids = []
    
    # 从custom.evidence.event_ids获取
    if 'custom' in finding and 'evidence' in finding.get('custom', {}):
        event_ids.extend(finding.get('custom', {}).get('evidence', {}).get('event_ids', []))
    
    # 从message中提取（如果有）
    message = finding.get('message', '')
    if 'event' in message.lower():
        # 尝试从message中提取event ID
        pass
    
    return event_ids


def group_findings_by_fingerprint(findings):
    """按fingerprint分组findings"""
    groups = defaultdict(list)
    for finding in findings:
        fingerprint = finding.get('custom', {}).get('finding', {}).get('fingerprint', 'unknown')
        groups[fingerprint].append(finding)
    return groups


def format_finding_summary(finding):
    """格式化finding摘要"""
    event_id = finding.get('event', {}).get('id', 'N/A')
    timestamp = finding.get('@timestamp', 'N/A')
    rule_name = finding.get('rule', {}).get('name', 'N/A')
    technique = finding.get('threat', {}).get('technique', {}).get('id', 'N/A')
    tactic = finding.get('threat', {}).get('tactic', {}).get('id', 'N/A')
    host_name = finding.get('host', {}).get('name', 'N/A')
    severity = finding.get('event', {}).get('severity', 'N/A')
    
    return {
        'event_id': event_id,
        'timestamp': timestamp,
        'rule_name': rule_name,
        'technique': technique,
        'tactic': tactic,
        'host_name': host_name,
        'severity': severity
    }


def main():
    """主函数"""
    print("=" * 100)
    print("Findings 链展示：Event -> Raw Finding -> Canonical Finding")
    print("=" * 100)
    
    # 1. 获取raw findings
    print("\n[步骤 1] 查询 Raw Findings...")
    raw_findings = get_raw_findings()
    print(f"✅ 找到 {len(raw_findings)} 个 Raw Findings")
    
    if not raw_findings:
        print("\n⚠️  没有找到 Raw Findings")
        print("提示: 请先运行检测:")
        print("  cd backend/opensearch/scripts")
        print("  uv run python test_detection.py --all")
        return 0
    
    # 2. 获取canonical findings
    print("\n[步骤 2] 查询 Canonical Findings...")
    canonical_findings = get_canonical_findings()
    print(f"✅ 找到 {len(canonical_findings)} 个 Canonical Findings")
    
    # 3. 按fingerprint分组raw findings
    print("\n[步骤 3] 分析 Findings 关联关系...")
    raw_groups = group_findings_by_fingerprint(raw_findings)
    
    # 4. 展示详细信息
    print("\n" + "=" * 100)
    print("Raw Findings 详情")
    print("=" * 100)
    
    for i, finding in enumerate(raw_findings[:20], 1):  # 只显示前20个
        summary = format_finding_summary(finding)
        fingerprint = finding.get('custom', {}).get('finding', {}).get('fingerprint', 'unknown')
        
        print(f"\n[{i}] Raw Finding ID: {finding.get('_id', 'N/A')[:20]}...")
        print(f"    Event ID: {summary['event_id']}")
        print(f"    时间戳: {summary['timestamp']}")
        print(f"    规则: {summary['rule_name']}")
        print(f"    攻击技术: {summary['technique']} ({summary['tactic']})")
        print(f"    主机: {summary['host_name']}")
        print(f"    严重程度: {summary['severity']}")
        print(f"    指纹: {fingerprint[:50]}...")
        
        # 显示相关事件
        event_ids = get_related_events(finding)
        if event_ids:
            print(f"    相关事件: {', '.join(event_ids[:3])}")
    
    if len(raw_findings) > 20:
        print(f"\n... 还有 {len(raw_findings) - 20} 个 Raw Findings")
    
    # 5. 展示canonical findings
    if canonical_findings:
        print("\n" + "=" * 100)
        print("Canonical Findings 详情")
        print("=" * 100)
        
        for i, canonical in enumerate(canonical_findings, 1):
            summary = format_finding_summary(canonical)
            fingerprint = canonical.get('custom', {}).get('finding', {}).get('fingerprint', 'unknown')
            
            print(f"\n[{i}] Canonical Finding ID: {canonical.get('_id', 'N/A')[:20]}...")
            print(f"    Event ID: {summary['event_id']}")
            print(f"    时间戳: {summary['timestamp']}")
            print(f"    规则: {summary['rule_name']}")
            print(f"    攻击技术: {summary['technique']} ({summary['tactic']})")
            print(f"    主机: {summary['host_name']}")
            print(f"    严重程度: {summary['severity']}")
            print(f"    指纹: {fingerprint[:50]}...")
            
            # 找到对应的raw findings
            matching_raw = raw_groups.get(fingerprint, [])
            print(f"    合并的 Raw Findings: {len(matching_raw)} 个")
            
            if matching_raw:
                print(f"    原始 Findings 列表:")
                for j, raw in enumerate(matching_raw[:5], 1):  # 只显示前5个
                    raw_summary = format_finding_summary(raw)
                    print(f"      {j}. Raw Finding {raw.get('_id', 'N/A')[:20]}...")
                    print(f"         - Event ID: {raw_summary['event_id']}")
                    print(f"         - 时间戳: {raw_summary['timestamp']}")
                    print(f"         - 规则: {raw_summary['rule_name']}")
                
                if len(matching_raw) > 5:
                    print(f"      ... 还有 {len(matching_raw) - 5} 个 Raw Findings")
            
            # 显示完整原始内容
            print(f"\n    {'='*98}")
            print(f"    完整原始内容 (JSON):")
            print(f"    {'='*98}")
            try:
                # 格式化JSON，使用缩进
                canonical_json = json.dumps(canonical, indent=2, ensure_ascii=False, default=str)
                # 每行添加缩进
                for line in canonical_json.split('\n'):
                    print(f"    {line}")
            except Exception as e:
                print(f"    ⚠️  无法格式化JSON: {e}")
                print(f"    原始内容: {str(canonical)[:500]}...")
    
    # 6. 统计信息
    print("\n" + "=" * 100)
    print("统计信息")
    print("=" * 100)
    
    print(f"\nRaw Findings:")
    print(f"  总数: {len(raw_findings)}")
    print(f"  唯一指纹数: {len(raw_groups)}")
    
    if canonical_findings:
        print(f"\nCanonical Findings:")
        print(f"  总数: {len(canonical_findings)}")
        print(f"  合并率: {len(canonical_findings) / len(raw_findings) * 100:.1f}%")
        
        # 按攻击技术统计
        technique_count = defaultdict(int)
        for canonical in canonical_findings:
            technique = canonical.get('threat', {}).get('technique', {}).get('id', 'Unknown')
            technique_count[technique] += 1
        
        print(f"\n按攻击技术统计:")
        for technique, count in sorted(technique_count.items(), key=lambda x: -x[1]):
            print(f"  {technique}: {count} 个")
    
    # 7. 展示关联关系图
    print("\n" + "=" * 100)
    print("关联关系图")
    print("=" * 100)
    
    if canonical_findings:
        for i, canonical in enumerate(canonical_findings, 1):
            fingerprint = canonical.get('custom', {}).get('finding', {}).get('fingerprint', 'unknown')
            matching_raw = raw_groups.get(fingerprint, [])
            
            print(f"\nCanonical Finding #{i}")
            print(f"  └─ 合并了 {len(matching_raw)} 个 Raw Findings:")
            for j, raw in enumerate(matching_raw[:10], 1):  # 只显示前10个
                raw_summary = format_finding_summary(raw)
                print(f"     {j}. Raw Finding: {raw_summary['rule_name']}")
                print(f"        └─ Event ID: {raw_summary['event_id']}")
                print(f"        └─ 时间: {raw_summary['timestamp']}")
                print(f"        └─ 主机: {raw_summary['host_name']}")
            
            if len(matching_raw) > 10:
                print(f"     ... 还有 {len(matching_raw) - 10} 个 Raw Findings")
    
    print("\n" + "=" * 100)
    print("展示完成！")
    print("=" * 100)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
