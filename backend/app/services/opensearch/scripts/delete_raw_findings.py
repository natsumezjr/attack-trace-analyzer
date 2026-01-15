#!/usr/bin/env python3
"""
删除所有 Raw Findings 索引

功能：
1. 删除所有 Raw Findings 索引
2. 保留其他索引（Events、Canonical Findings等）
"""

import sys
from pathlib import Path

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client, get_index_name, INDEX_PATTERNS


def delete_raw_findings():
    """删除所有Raw Findings索引"""
    client = get_client()
    
    print("=" * 80)
    print("删除所有 Raw Findings 索引")
    print("=" * 80)
    
    deleted_count = 0
    
    # 获取所有Raw Findings索引
    print("\n[1] 查找 Raw Findings 索引...")
    raw_pattern = INDEX_PATTERNS['RAW_FINDINGS']
    
    try:
        # 获取所有匹配的索引
        indices = client.indices.get_alias(index=f"*raw-findings*")
        raw_indices = list(indices.keys())
        
        if raw_indices:
            print(f"  找到 {len(raw_indices)} 个Raw Findings索引:")
            for idx in raw_indices:
                try:
                    stats = client.count(index=idx)
                    count = stats.get('count', 0)
                    print(f"    - {idx} ({count:,} 个文档)")
                except:
                    print(f"    - {idx}")
            
            # 确认删除
            print(f"\n[2] 准备删除 {len(raw_indices)} 个索引...")
            
            # 删除索引
            for idx in raw_indices:
                try:
                    client.indices.delete(index=idx)
                    print(f"  [OK] 已删除: {idx}")
                    deleted_count += 1
                except Exception as e:
                    print(f"  [ERROR] 删除失败 {idx}: {e}")
        else:
            print("  [INFO] 没有找到Raw Findings索引")
    except Exception as e:
        print(f"  [WARNING] 查询Raw Findings索引失败: {e}")
    
    # 总结
    print("\n" + "=" * 80)
    print("删除完成")
    print("=" * 80)
    print(f"\n总共删除了 {deleted_count} 个Raw Findings索引")
    
    if deleted_count > 0:
        print("\n现在可以运行检测来重新生成Raw Findings:")
        print("  cd backend/opensearch/scripts")
        print("  uv run python run_analysis_direct.py --analysis")
    
    return deleted_count


def main():
    """主函数"""
    delete_raw_findings()
    return 0


if __name__ == "__main__":
    sys.exit(main())
