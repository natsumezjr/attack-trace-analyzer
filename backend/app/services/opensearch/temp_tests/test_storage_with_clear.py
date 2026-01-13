#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试存储功能（先清除已有数据，再测试存储）
"""
import sys
import io
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from .. import run_security_analytics, get_client, get_index_name, INDEX_PATTERNS
from datetime import datetime

print("=" * 60)
print("测试存储功能（先清除已有数据）")
print("=" * 60)

try:
    client = get_client()
    today = datetime.now()
    
    # 步骤1: 检查当前数据
    print("\n[步骤1] 检查当前数据")
    raw_idx = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    raw_count_before = client.count(index=raw_idx).get('count', 0) if client.indices.exists(index=raw_idx) else 0
    print(f"  当前Raw Findings数量: {raw_count_before}")
    
    # 步骤2: 清除已有数据（如果需要）
    if raw_count_before > 0:
        print(f"\n[步骤2] 清除已有数据（{raw_count_before}条）")
        client.delete_by_query(
            index=raw_idx,
            body={"query": {"match_all": {}}}
        )
        client.indices.refresh(index=raw_idx)
        print("  ✅ 已清除")
    else:
        print("\n[步骤2] 无需清除（数据为空）")
    
    # 步骤3: 运行检测和存储
    print("\n[步骤3] 运行检测和存储")
    result = run_security_analytics(trigger_scan=True)
    
    print("\n[结果]")
    print(f"  成功: {result.get('success', False)}")
    print(f"  Findings数量: {result.get('findings_count', 0)}")
    print(f"  转换后: {result.get('converted_count', 0)}")
    print(f"  存储成功: {result.get('stored', 0)}")
    print(f"  存储失败: {result.get('failed', 0)}")
    print(f"  重复跳过: {result.get('duplicated', 0)}")
    print(f"  来源: {result.get('source', 'unknown')}")
    
    # 步骤4: 验证存储结果
    print("\n[步骤4] 验证存储结果")
    raw_count_after = client.count(index=raw_idx).get('count', 0) if client.indices.exists(index=raw_idx) else 0
    print(f"  存储后Raw Findings数量: {raw_count_after}")
    
    if result.get('stored', 0) > 0:
        print("\n[✅ 成功] Findings存储功能正常！")
        print(f"  存储了 {result.get('stored', 0)} 条findings")
        if raw_count_after == result.get('stored', 0):
            print("  ✅ 索引中的数量与存储结果一致")
        else:
            print(f"  ⚠️  索引中的数量 ({raw_count_after}) 与存储结果 ({result.get('stored', 0)}) 不一致")
    elif result.get('duplicated', 0) > 0:
        print("\n[⚠️  警告] 所有findings都被跳过了（重复）")
        print("  这可能是因为：")
        print("    1. 清除操作未生效")
        print("    2. findings的event.id相同但时间戳不同")
    else:
        print("\n[❌ 失败] 没有存储任何findings")
        print("  可能原因：")
        print("    1. 没有findings生成")
        print("    2. 转换失败")
        print("    3. 存储失败")
    
    print("\n" + "=" * 60)
    
except Exception as e:
    print(f"[ERROR] 测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
