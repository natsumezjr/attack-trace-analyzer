#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenSearch Findings 数据清理工具

功能说明：
    清除 OpenSearch 中的 raw-findings 和 canonical-findings 索引数据。
    此工具用于测试前清空已有数据，以便重新验证存储功能。

使用场景：
    - 在运行测试脚本之前，清除旧的测试数据
    - 在调试存储功能时，反复测试数据写入
    - 清理测试环境中的告警数据

注意事项：
    - 此操作会永久删除数据，请谨慎操作
    - 删除前会显示数据条数并要求确认
    - 需要先启动 OpenSearch 服务

环境要求：
    - OpenSearch 服务运行中
    - 已配置环境变量（OPENSEARCH_URL等）

运行方式：
    cd backend
    uv run python scripts/opensearch/clear_findings_data.py
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

from app.services.opensearch import get_client, get_index_name, INDEX_PATTERNS
from datetime import datetime

print("=" * 60)
print("OpenSearch Findings 数据清理工具")
print("=" * 60)

try:
    client = get_client()
    today = datetime.now()

    # 检查并清除 raw-findings 索引
    raw_idx = get_index_name(INDEX_PATTERNS['RAW_FINDINGS'], today)
    if client.indices.exists(index=raw_idx):
        raw_count = client.count(index=raw_idx).get('count', 0)
        print(f"\n[Raw Findings 索引]")
        print(f"  索引名: {raw_idx}")
        print(f"  文档数: {raw_count}")

        if raw_count > 0:
            confirm = input(f"\n是否删除 {raw_count} 条 raw-findings 数据？(y/N): ")
            if confirm.lower() == 'y':
                client.delete_by_query(
                    index=raw_idx,
                    body={"query": {"match_all": {}}}
                )
                client.indices.refresh(index=raw_idx)
                print("  ✅ 已清除 raw-findings 数据")
            else:
                print("  ⏭️  跳过清除 raw-findings")
        else:
            print("  ℹ️  索引为空，无需清除")
    else:
        print(f"\n[Raw Findings 索引]")
        print(f"  索引不存在: {raw_idx}")

    # 检查并清除 canonical-findings 索引
    canonical_idx = get_index_name(INDEX_PATTERNS['CANONICAL_FINDINGS'], today)
    if client.indices.exists(index=canonical_idx):
        canonical_count = client.count(index=canonical_idx).get('count', 0)
        print(f"\n[Canonical Findings 索引]")
        print(f"  索引名: {canonical_idx}")
        print(f"  文档数: {canonical_count}")

        if canonical_count > 0:
            confirm = input(f"\n是否删除 {canonical_count} 条 canonical-findings 数据？(y/N): ")
            if confirm.lower() == 'y':
                client.delete_by_query(
                    index=canonical_idx,
                    body={"query": {"match_all": {}}}
                )
                client.indices.refresh(index=canonical_idx)
                print("  ✅ 已清除 canonical-findings 数据")
            else:
                print("  ⏭️  跳过清除 canonical-findings")
        else:
            print("  ℹ️  索引为空，无需清除")
    else:
        print(f"\n[Canonical Findings 索引]")
        print(f"  索引不存在: {canonical_idx}")

    print("\n" + "=" * 60)
    print("清除完成！现在可以重新运行测试来验证存储功能。")

except Exception as e:
    print(f"[ERROR] 清除失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
