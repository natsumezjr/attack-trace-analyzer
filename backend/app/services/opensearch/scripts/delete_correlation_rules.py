#!/usr/bin/env python3
"""
删除所有 Correlation Rules

功能：
1. 列出所有 correlation rules
2. 删除所有 correlation rules（或指定名称的规则）
3. 可选：只列出不删除

使用方法:
    # 列出所有rules
    uv run python delete_correlation_rules.py --list-only
    
    # 删除所有rules
    uv run python delete_correlation_rules.py --yes
    
    # 删除指定名称的rule
    uv run python delete_correlation_rules.py --name "Lateral Movement Detection" --yes
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client

# Correlation Rules API
CORRELATION_RULES_API = "/_plugins/_security_analytics/correlation/rules"


def list_all_correlation_rules():
    """列出所有 correlation rules"""
    client = get_client()
    
    print("=" * 80)
    print("查询所有 Correlation Rules")
    print("=" * 80)
    
    try:
        # 搜索所有 rules
        response = client.transport.perform_request(
            'POST',
            f"{CORRELATION_RULES_API}/_search",
            body={
                "query": {"match_all": {}},
                "size": 100
            }
        )
        
        hits = response.get('hits', {}).get('hits', [])
        total = response.get('hits', {}).get('total', {})
        if isinstance(total, dict):
            total_count = total.get('value', len(hits))
        else:
            total_count = total
        
        print(f"\n找到 {total_count} 个 Correlation Rules")
        
        if hits:
            print("\n规则列表:")
            for i, hit in enumerate(hits, 1):
                rule_id = hit.get('_id')
                source = hit.get('_source', {})
                rule_name = source.get('name', 'Unknown')
                enabled = source.get('enabled', True)
                status = "[启用]" if enabled else "[禁用]"
                
                print(f"\n{i}. {status} {rule_name}")
                print(f"   ID: {rule_id}")
                
                # 显示查询数量
                correlate = source.get('correlate', [])
                if correlate:
                    print(f"   查询数量: {len(correlate)}")
                    for j, q in enumerate(correlate, 1):
                        category = q.get('category', 'unknown')
                        index = q.get('index', 'unknown')
                        print(f"     Query {j}: {category} ({index})")
        else:
            print("\n[INFO] 没有找到 Correlation Rules")
        
        return hits
        
    except Exception as e:
        print(f"[ERROR] 查询失败: {e}")
        import traceback
        traceback.print_exc()
        return []


def delete_correlation_rule(rule_id: str) -> bool:
    """删除单个 correlation rule"""
    client = get_client()
    
    try:
        client.transport.perform_request(
            'DELETE',
            f"{CORRELATION_RULES_API}/{rule_id}"
        )
        return True
    except Exception as e:
        print(f"[ERROR] 删除失败 {rule_id}: {e}")
        return False


def delete_all_correlation_rules(filter_name: str = None, auto_confirm: bool = False):
    """删除所有 correlation rules（可选：只删除指定名称的）"""
    client = get_client()
    
    print("=" * 80)
    if filter_name:
        print(f"删除 Correlation Rule: {filter_name}")
    else:
        print("删除所有 Correlation Rules")
    print("=" * 80)
    
    # 1. 列出所有 rules
    print("\n[1] 查询所有 Correlation Rules...")
    rules = list_all_correlation_rules()
    
    if not rules:
        print("\n[INFO] 没有需要删除的 rules")
        return 0
    
    # 2. 过滤（如果指定了名称）
    rules_to_delete = rules
    if filter_name:
        rules_to_delete = [r for r in rules if r.get('_source', {}).get('name', '').lower() == filter_name.lower()]
        if not rules_to_delete:
            print(f"\n[INFO] 没有找到名称为 '{filter_name}' 的 rule")
            return 0
        print(f"\n[2] 过滤后，需要删除 {len(rules_to_delete)} 个 rule:")
        for rule in rules_to_delete:
            rule_name = rule.get('_source', {}).get('name', 'Unknown')
            rule_id = rule.get('_id')
            print(f"   - {rule_name} (ID: {rule_id[:50]}...)")
    
    # 3. 确认删除
    if not auto_confirm:
        if filter_name:
            response = input(f"\n确认删除 rule '{filter_name}'？(yes/no): ").strip().lower()
        else:
            response = input(f"\n确认删除所有 {len(rules_to_delete)} 个 rules？(yes/no): ").strip().lower()
        
        if response != 'yes':
            print("[INFO] 取消删除")
            return 0
    
    # 4. 删除 rules
    print(f"\n[3] 开始删除 rules...")
    deleted_count = 0
    failed_count = 0
    
    for rule in rules_to_delete:
        rule_id = rule.get('_id')
        rule_name = rule.get('_source', {}).get('name', 'Unknown')
        
        print(f"  删除: {rule_name} (ID: {rule_id[:50]}...)")
        if delete_correlation_rule(rule_id):
            print(f"    [OK] 已删除")
            deleted_count += 1
        else:
            print(f"    [ERROR] 删除失败")
            failed_count += 1
    
    print("\n" + "=" * 80)
    print("删除完成")
    print("=" * 80)
    print(f"  成功删除: {deleted_count} 个")
    print(f"  删除失败: {failed_count} 个")
    print(f"  总计: {len(rules_to_delete)} 个")
    
    return deleted_count


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="删除 OpenSearch Security Analytics Correlation Rules")
    parser.add_argument(
        "--name",
        type=str,
        help="只删除指定名称的rule（如：'Lateral Movement Detection'）"
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="只列出rules，不删除"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="自动确认删除（不需要交互确认）"
    )
    
    args = parser.parse_args()
    
    if args.list_only:
        list_all_correlation_rules()
    else:
        delete_all_correlation_rules(filter_name=args.name, auto_confirm=args.yes)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
