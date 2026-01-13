#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试告警去重功能
"""
import sys
import io
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from .. import deduplicate_findings

print("=" * 60)
print("测试告警去重功能")
print("=" * 60)

try:
    result = deduplicate_findings()
    
    print("\n[结果]")
    print(f"  原始findings: {result.get('total', 0)}")
    print(f"  合并数量: {result.get('merged', 0)}")
    print(f"  Canonical findings: {result.get('canonical', 0)}")
    print(f"  错误: {result.get('errors', 0)}")
    
    if result.get('canonical', 0) > 0:
        print("\n[OK] 告警去重成功！")
        if result.get('merged', 0) > 0:
            print(f"  合并了 {result.get('merged', 0)} 个findings")
    else:
        print("\n[WARNING] 没有生成canonical findings")
        print("  可能原因：")
        print("    1. 没有raw-findings数据")
        print("    2. 没有需要合并的findings（所有findings都是唯一的）")
    
    print("\n" + "=" * 60)
    
except Exception as e:
    print(f"[ERROR] 测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
