#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenSearch Security Analytics 预打包规则查询脚本

功能：
1. 查询 OpenSearch Security Analytics 内置的预打包规则
2. 列出可用的预打包规则（按类别）
3. 预打包规则已经内置在 OpenSearch 中，无需导入

使用方法:
    python import_sigma_rules.py [选项]

选项:
    --list             列出所有可用的预打包规则类别
    --auto             自动模式：检查预打包规则是否可用
"""

import argparse
import sys
from pathlib import Path

# 添加 backend 目录到路径，以便从 opensearch 包和 app 模块导入
# 脚本在 backend/app/services/opensearch/scripts/，需要回到 backend/ 才能导入 app 和 opensearch 包
backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

# 延迟导入 opensearch 模块（仅在需要时）
def get_client():
    """延迟导入 get_client"""
    try:
        from app.services.opensearch.internal import get_client as _get_client
        return _get_client()
    except ImportError as e:
        print("\n[ERROR] 无法导入 opensearch 模块")
        print(f"  错误: {e}")
        print("提示: 请使用 uv run 运行此脚本:")
        print("     uv run python import_sigma_rules.py [选项]")
        print("\n或者确保已安装依赖:")
        print("     uv sync")
        raise


def list_prepackaged_categories():
    """列出所有可用的预打包规则类别"""
    client = get_client()
    
    print("\n查询预打包规则类别...")
    print("=" * 80)
    
    try:
        # 查询所有预打包规则
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/rules/_search',
            body={
                "query": {"match_all": {}},
                "size": 10000
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        total = response.get('hits', {}).get('total', {}).get('value', len(hits))
        
        # 统计预打包规则按类别分布
        categories = {}
        
        for hit in hits:
            rule_index = hit.get('_index', '')
            rule_source = hit.get('_source', {})
            category = rule_source.get('category', 'unknown')
            
            # 判断是否是预打包规则
            is_prepackaged = (
                'pre-packaged' in rule_index.lower() or 
                'prepackaged' in rule_index.lower() or
                rule_source.get('prePackaged', False) or
                rule_source.get('pre_packaged', False)
            )
            
            if is_prepackaged:
                if category not in categories:
                    categories[category] = {
                        'count': 0,
                        'rules': []
                    }
                categories[category]['count'] += 1
                rule_id = hit.get('_id')
                rule_title = rule_source.get('title', rule_id)
                categories[category]['rules'].append({
                    'id': rule_id,
                    'title': rule_title
                })
        
        if categories:
            print(f"\n找到 {len(categories)} 个预打包规则类别（共 {total} 个规则）:\n")
            for cat, info in sorted(categories.items()):
                print(f"  {cat}: {info['count']} 个规则")
                # 显示前5个规则示例
                if info['rules']:
                    print(f"    示例:")
                    for rule in info['rules'][:5]:
                        print(f"      - {rule['title']} (ID: {rule['id'][:50]}...)")
                    if len(info['rules']) > 5:
                        print(f"      ... 还有 {len(info['rules']) - 5} 个规则")
                print()
        else:
            print("\n[WARNING] 未找到预打包规则")
            print("[INFO] 可能原因:")
            print("  1. OpenSearch Security Analytics 插件未正确安装")
            print("  2. 预打包规则索引未创建")
            print("  3. 需要重启 OpenSearch 服务")
        
    except Exception as e:
        print(f"[ERROR] 查询预打包规则失败: {e}")
        import traceback
        traceback.print_exc()


def check_prepackaged_rules():
    """检查预打包规则是否可用"""
    print("=" * 80)
    print("检查 OpenSearch Security Analytics 预打包规则")
    print("=" * 80)
    print("\n注意：预打包规则已经内置在 OpenSearch 中，无需导入")
    print("本脚本仅用于检查预打包规则是否可用\n")
    
    client = get_client()
    
    try:
        # 查询所有预打包规则
        response = client.transport.perform_request(
            'POST',
            '/_plugins/_security_analytics/rules/_search',
            body={
                "query": {"match_all": {}},
                "size": 1000
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        total = response.get('hits', {}).get('total', {}).get('value', len(hits))
        
        # 统计预打包规则
        prepackaged_rules = []
        custom_rules = []
        categories = {}
        
        for hit in hits:
            rule_id = hit.get('_id')
            rule_index = hit.get('_index', '')
            rule_source = hit.get('_source', {})
            category = rule_source.get('category', 'unknown')
            
            # 判断是否是预打包规则
            is_prepackaged = (
                'pre-packaged' in rule_index.lower() or 
                'prepackaged' in rule_index.lower() or
                rule_source.get('prePackaged', False) or
                rule_source.get('pre_packaged', False)
            )
            
            if is_prepackaged:
                prepackaged_rules.append(rule_id)
                if category not in categories:
                    categories[category] = []
                categories[category].append(rule_id)
            else:
                custom_rules.append(rule_id)
        
        print(f"规则统计:")
        print(f"  预打包规则: {len(prepackaged_rules)} 个")
        print(f"  自定义规则: {len(custom_rules)} 个")
        print(f"  总计: {total} 个")
        
        if prepackaged_rules:
            print(f"\n预打包规则按类别分布:")
            for cat, rules in sorted(categories.items()):
                print(f"  {cat}: {len(rules)} 个")
            
            print(f"\n[OK] 预打包规则可用，可以直接使用")
            print(f"[INFO] 可以使用 setup_security_analytics.py 创建detector:")
            print(f"  uv run python setup_security_analytics.py --multiple")
        else:
            print(f"\n[WARNING] 未找到预打包规则")
            print(f"[INFO] 可能原因:")
            print(f"  1. OpenSearch Security Analytics 插件未正确安装")
            print(f"  2. 预打包规则索引未创建")
            print(f"  3. 需要重启 OpenSearch 服务")
        
        return 0
        
    except Exception as e:
        print(f"[ERROR] 查询预打包规则失败: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="查询 OpenSearch Security Analytics 预打包规则",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--list", action="store_true", help="列出所有可用的预打包规则类别")
    parser.add_argument("--auto", action="store_true", help="自动模式：检查预打包规则是否可用")
    
    args = parser.parse_args()
    
    # 如果没有指定任何选项，默认使用 --auto
    if not args.list and not args.auto:
        args.auto = True
    
    if args.list:
        list_prepackaged_categories()
    elif args.auto:
        check_prepackaged_rules()
    
    print("\n" + "=" * 80)
    print("完成")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
