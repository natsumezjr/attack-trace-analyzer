#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
清除已有的findings数据（用于测试存储功能）
"""
import sys
import io
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from .. import get_client, get_index_name, INDEX_PATTERNS
from datetime import datetime

print("=" * 60)
print("清除已有的Findings数据")
print("=" * 60)

try:
    client = get_client()
    today = datetime.now()
    
    # 检查并清除raw-findings索引
    raw_idx = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    if client.indices.exists(index=raw_idx):
        raw_count = client.count(index=raw_idx).get('count', 0)
        print(f"\n[Raw Findings索引]")
        print(f"  索引名: {raw_idx}")
        print(f"  文档数: {raw_count}")
        
        if raw_count > 0:
            confirm = input(f"\n是否删除 {raw_count} 条raw-findings数据？(y/N): ")
            if confirm.lower() == 'y':
                client.delete_by_query(
                    index=raw_idx,
                    body={"query": {"match_all": {}}}
                )
                client.indices.refresh(index=raw_idx)
                print("  ✅ 已清除raw-findings数据")
            else:
                print("  ⏭️  跳过清除raw-findings")
        else:
            print("  ℹ️  索引为空，无需清除")
    else:
        print(f"\n[Raw Findings索引]")
        print(f"  索引不存在: {raw_idx}")
    
    # 检查并清除canonical-findings索引
    canonical_idx = get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], today)
    if client.indices.exists(index=canonical_idx):
        canonical_count = client.count(index=canonical_idx).get('count', 0)
        print(f"\n[Canonical Findings索引]")
        print(f"  索引名: {canonical_idx}")
        print(f"  文档数: {canonical_count}")
        
        if canonical_count > 0:
            confirm = input(f"\n是否删除 {canonical_count} 条canonical-findings数据？(y/N): ")
            if confirm.lower() == 'y':
                client.delete_by_query(
                    index=canonical_idx,
                    body={"query": {"match_all": {}}}
                )
                client.indices.refresh(index=canonical_idx)
                print("  ✅ 已清除canonical-findings数据")
            else:
                print("  ⏭️  跳过清除canonical-findings")
        else:
            print("  ℹ️  索引为空，无需清除")
    else:
        print(f"\n[Canonical Findings索引]")
        print(f"  索引不存在: {canonical_idx}")
    
    print("\n" + "=" * 60)
    print("清除完成！现在可以重新运行测试来验证存储功能。")
    
except Exception as e:
    print(f"[ERROR] 清除失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
