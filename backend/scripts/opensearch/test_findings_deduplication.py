#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenSearch Findings 告警去重测试工具

功能说明：
    测试告警去重功能，将 raw-findings 合并为 canonical-findings。
    此工具用于验证去重逻辑是否正常工作。

测试内容：
    - 读取 raw-findings 索引中的告警数据
    - 根据去重规则合并相似的告警
    - 生成 canonical-findings
    - 显示去重结果统计

使用场景：
    - 验证告警去重功能是否正常
    - 查看重命并效果和统计信息
    - 调试去重逻辑问题

环境要求：
    - OpenSearch 服务运行中
    - 已配置环境变量（OPENSEARCH_URL等）
    - raw-findings 索引中有数据

运行方式：
    cd backend
    uv run python scripts/opensearch/test_findings_deduplication.py
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

from app.services.opensearch import deduplicate_findings

print("=" * 60)
print("OpenSearch Findings 告警去重测试")
print("=" * 60)

try:
    result = deduplicate_findings()
    
    print("\n[去重结果]")
    print(f"  原始 findings: {result.get('total', 0)}")
    print(f"  合并数量: {result.get('merged', 0)}")
    print(f"  Canonical findings: {result.get('canonical', 0)}")
    print(f"  错误: {result.get('errors', 0)}")

    if result.get('canonical', 0) > 0:
        print("\n[OK] 告警去重成功！")
        if result.get('merged', 0) > 0:
            print(f"  合并了 {result.get('merged', 0)} 个 findings")
    else:
        print("\n[WARNING] 没有生成 canonical findings")
        print("  可能原因：")
        print("    1. 没有 raw-findings 数据")
        print("    2. 没有需要合并的 findings（所有 findings 都是唯一的）")
    
    print("\n" + "=" * 60)
    
except Exception as e:
    print(f"[ERROR] 测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
