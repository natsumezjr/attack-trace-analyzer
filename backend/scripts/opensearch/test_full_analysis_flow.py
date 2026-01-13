#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenSearch 完整分析流程测试工具

功能说明：
    测试完整的安全分析流程，包括检测和去重两个步骤。
    此工具用于验证从事件到 canonical findings 的完整流程。

测试内容：
    1. 运行 Security Analytics 检测，生成 raw-findings
    2. 运行告警去重，生成 canonical-findings
    3. 统计和验证所有索引的数据

使用场景：
    - 验证完整分析流程
    - 端到端测试
    - 验证数据流转是否正常

环境要求：
    - OpenSearch 服务运行中
    - 已配置环境变量（OPENSEARCH_URL等）
    - Security Analytics 已配置
    - 事件数据已存在

运行方式：
    cd backend
    uv run python scripts/opensearch/test_full_analysis_flow.py
"""
import sys
import io
from pathlib import Path

# Windows UTF-8 兼容
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 添加 backend 目录到 Python 路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch import run_data_analysis, get_client, get_index_name, INDEX_PATTERNS
from datetime import datetime

print("=" * 60)
print("OpenSearch 完整分析流程测试")
print("=" * 60)

try:
    # 运行完整流程
    result = run_data_analysis(trigger_scan=True)
    
    print("\n[检测结果]")
    detection = result.get('detection', {})
    print(f"  成功: {detection.get('success', False)}")
    print(f"  Findings数量: {detection.get('findings_count', 0)}")
    print(f"  存储成功: {detection.get('stored', 0)}")
    print(f"  来源: {detection.get('source', 'unknown')}")
    
    print("\n[去重结果]")
    deduplication = result.get('deduplication', {})
    print(f"  原始findings: {deduplication.get('total', 0)}")
    print(f"  合并数量: {deduplication.get('merged', 0)}")
    print(f"  Canonical findings: {deduplication.get('canonical', 0)}")
    
    # 检查所有索引的数据
    print("\n[索引数据统计]")
    client = get_client()
    today = datetime.now()
    
    # 检查事件索引
    events_idx = get_index_name(INDEX_PATTERNS['ECS_EVENTS'], today)
    events_count = client.count(index=events_idx).get('count', 0) if client.indices.exists(index=events_idx) else 0
    print(f"  事件数量: {events_count}")
    
    # 检查raw-findings索引
    raw_idx = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    raw_count = client.count(index=raw_idx).get('count', 0) if client.indices.exists(index=raw_idx) else 0
    print(f"  Raw Findings数量: {raw_count}")
    
    # 检查canonical-findings索引
    canonical_idx = get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], today)
    canonical_count = client.count(index=canonical_idx).get('count', 0) if client.indices.exists(index=canonical_idx) else 0
    print(f"  Canonical Findings数量: {canonical_count}")
    
    # 总结
    print("\n[总结]")
    if events_count > 0 and raw_count > 0:
        print("  ✅ 事件数据存在")
        print("  ✅ Raw Findings已生成")
        if canonical_count > 0:
            print("  ✅ Canonical Findings已生成")
            if canonical_count <= raw_count:
                print("  ✅ 去重逻辑正常（canonical数量 <= raw数量）")
            else:
                print("  ⚠️  警告：canonical数量 > raw数量（可能有问题）")
        else:
            print("  ⚠️  Canonical Findings未生成（可能没有需要合并的findings）")
    else:
        print("  ⚠️  数据不完整，请检查")
    
    print("\n" + "=" * 60)
    
except Exception as e:
    print(f"[ERROR] 测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
