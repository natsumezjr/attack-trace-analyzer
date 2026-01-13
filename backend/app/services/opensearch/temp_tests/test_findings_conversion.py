#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试findings转换和存储
"""
import sys
import io
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from .. import run_security_analytics

print("=" * 60)
print("测试Findings转换和存储")
print("=" * 60)

try:
    result = run_security_analytics(trigger_scan=True)
    
    print("\n[结果]")
    print(f"  成功: {result.get('success', False)}")
    print(f"  Findings数量: {result.get('findings_count', 0)}")
    print(f"  转换后: {result.get('converted_count', 0)}")
    print(f"  存储成功: {result.get('stored', 0)}")
    print(f"  存储失败: {result.get('failed', 0)}")
    print(f"  重复跳过: {result.get('duplicated', 0)}")
    print(f"  来源: {result.get('source', 'unknown')}")
    
    if result.get('stored', 0) > 0:
        print("\n[OK] Findings转换和存储成功！")
    elif result.get('duplicated', 0) > 0:
        print("\n[OK] Findings转换成功，但因为重复已跳过存储（这是正常的）")
        print("  说明：这些findings之前已经存储过了，系统自动去重")
    else:
        print("\n[WARNING] 没有存储任何findings")
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
