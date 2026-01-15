#!/usr/bin/env python3
"""
展示 Raw Findings 的数据结构

功能：
1. 查询 raw-findings 索引
2. 展示一个完整的 raw finding 文档结构
3. 说明各个字段的含义
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS


def show_raw_findings_structure():
    """展示 raw findings 的数据结构"""
    client = get_client()
    today = datetime.now()
    raw_index = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    
    print("=" * 80)
    print("Raw Findings 数据结构说明")
    print("=" * 80)
    
    # 检查索引是否存在
    if not client.indices.exists(index=raw_index):
        print(f"\n[WARNING] 索引 {raw_index} 不存在")
        print("请先运行分析生成 raw findings:")
        print("  from app.services.opensearch.analysis import run_data_analysis")
        print("  run_data_analysis()")
        return
    
    try:
        # 查询一个 raw finding
        response = client.search(
            index=raw_index,
            body={
                "size": 1,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        
        if not hits:
            print(f"\n[WARNING] 索引 {raw_index} 中没有数据")
            return
        
        finding = hits[0].get('_source', {})
        doc_id = hits[0].get('_id')
        
        print(f"\n找到 Raw Finding:")
        print(f"  文档 _id: {doc_id}")
        print(f"  索引: {raw_index}")
        
        print("\n" + "=" * 80)
        print("完整的 Raw Finding 文档结构")
        print("=" * 80)
        print(json.dumps(finding, indent=2, ensure_ascii=False))
        
        print("\n" + "=" * 80)
        print("字段说明")
        print("=" * 80)
        
        # 说明各个字段
        field_descriptions = {
            "@timestamp": "时间戳（UTC），事件的原始时间",
            "ecs.version": "ECS 规范版本",
            "event.id": "Finding 的唯一标识符（如 sa-finding-xxx）",
            "event.kind": "事件类型，固定为 'alert'",
            "event.category": "事件类别，如 ['intrusion_detection']",
            "event.type": "事件类型，如 ['alert']",
            "event.action": "事件动作，如 'security_analytics_detection'",
            "event.dataset": "数据集，如 'finding.raw.security_analytics'",
            "event.severity": "严重程度（0-100）",
            "event.created": "事件创建时间（UTC）",
            "event.ingested": "事件入库时间（UTC）",
            "rule.id": "规则 ID（如 sa-rule-xxx）",
            "rule.name": "规则名称",
            "rule.version": "规则版本",
            "threat.tactic.id": "ATT&CK Tactic ID（如 TA0001）",
            "threat.tactic.name": "ATT&CK Tactic 名称（如 Initial Access）",
            "threat.technique.id": "ATT&CK Technique ID（如 T1078）",
            "threat.technique.name": "ATT&CK Technique 名称",
            "custom.finding.stage": "Finding 阶段，固定为 'raw'",
            "custom.finding.providers": "检测引擎来源（如 ['security_analytics']）",
            "custom.finding.fingerprint": "Finding 指纹（用于去重）",
            "custom.finding.detector_id": "Detector ID（用于增量处理）",
            "custom.confidence": "置信度（0.0-1.0）",
            "custom.evidence.event_ids": "相关事件的 UUID 列表（Security Analytics 的引用）",
            "custom.evidence.document_ids": "相关事件的文档 _id 列表（用于直接查询）",
            "host.id": "主机 ID",
            "host.name": "主机名称",
            "message": "Finding 描述信息"
        }
        
        print("\n主要字段:")
        for field, desc in field_descriptions.items():
            value = finding
            for key in field.split('.'):
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    value = None
                    break
            
            if value is not None:
                if isinstance(value, list) and len(value) > 3:
                    display_value = str(value[:3]) + f"... (共{len(value)}个)"
                elif isinstance(value, str) and len(value) > 50:
                    display_value = value[:50] + "..."
                else:
                    display_value = value
                print(f"\n  {field}:")
                print(f"    值: {display_value}")
                print(f"    说明: {desc}")
        
        # 展示一个简化的示例结构
        print("\n" + "=" * 80)
        print("简化的 Raw Finding 示例结构")
        print("=" * 80)
        
        example = {
            "@timestamp": "2026-01-14T10:30:00Z",
            "event": {
                "id": "sa-finding-1234567890",
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["alert"],
                "action": "security_analytics_detection",
                "dataset": "finding.raw.security_analytics",
                "severity": 50,
                "created": "2026-01-14T10:30:00Z",
                "ingested": "2026-01-14T10:30:00Z"
            },
            "rule": {
                "id": "sa-rule-detector-001",
                "name": "Suspicious DNS Query",
                "version": "1.0"
            },
            "threat": {
                "tactic": {
                    "id": "TA0011",
                    "name": "Command and Control"
                },
                "technique": {
                    "id": "T1071",
                    "name": "Application Layer Protocol"
                }
            },
            "custom": {
                "finding": {
                    "stage": "raw",
                    "providers": ["security_analytics"],
                    "fingerprint": "fp-abc123...",
                    "detector_id": "detector-001"
                },
                "confidence": 0.7,
                "evidence": {
                    "event_ids": ["uuid-1", "uuid-2"],
                    "document_ids": ["doc-id-1", "doc-id-2"]
                }
            },
            "host": {
                "id": "host-001",
                "name": "server-01"
            },
            "message": "Security Analytics detection from detector-name"
        }
        
        print(json.dumps(example, indent=2, ensure_ascii=False))
        
    except Exception as e:
        print(f"\n[ERROR] 查询失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    show_raw_findings_structure()
