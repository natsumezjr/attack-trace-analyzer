#!/usr/bin/env python3
"""
设置 OpenSearch HTTP 行长度限制

通过 API 动态设置 http.max_initial_line_length，避免 correlation 查询时 URL 过长错误。
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.opensearch.internal import get_client


def set_http_line_length(length: str = "16kb"):
    """
    设置 OpenSearch HTTP 行长度限制
    
    参数：
    - length: 长度值，如 "16kb", "32kb" 等
    """
    client = get_client()
    
    try:
        # 使用 transient 设置（重启后失效，但不需要重启节点）
        # 使用 persistent 设置（重启后仍然有效）
        response = client.cluster.put_settings(
            body={
                "persistent": {
                    "http.max_initial_line_length": length
                }
            }
        )
        
        print(f"[OK] 成功设置 http.max_initial_line_length = {length}")
        print(f"响应: {response}")
        return True
        
    except Exception as e:
        print(f"[ERROR] 设置失败: {e}")
        
        # 尝试使用 transient
        try:
            response = client.cluster.put_settings(
                body={
                    "transient": {
                        "http.max_initial_line_length": length
                    }
                }
            )
            print(f"[OK] 使用 transient 设置成功: {length}")
            print(f"响应: {response}")
            return True
        except Exception as e2:
            print(f"[ERROR] transient 设置也失败: {e2}")
            return False


def check_current_setting():
    """检查当前的 HTTP 行长度设置"""
    client = get_client()
    
    try:
        response = client.cluster.get_settings(
            include_defaults=True,
            filter_path="*.http.max_initial_line_length"
        )
        
        print("\n当前 HTTP 行长度设置:")
        print(f"{response}")
        
        # 提取值
        defaults = response.get("defaults", {}).get("network", {}).get("http", {}).get("max_initial_line_length", "4kb")
        persistent = response.get("persistent", {}).get("network", {}).get("http", {}).get("max_initial_line_length")
        transient = response.get("transient", {}).get("network", {}).get("http", {}).get("max_initial_line_length")
        
        print(f"\n默认值: {defaults}")
        if persistent:
            print(f"持久设置: {persistent}")
        if transient:
            print(f"临时设置: {transient}")
        
        # 实际生效的值（优先级：transient > persistent > defaults）
        effective = transient or persistent or defaults
        print(f"\n实际生效值: {effective}")
        
        return effective
        
    except Exception as e:
        print(f"[ERROR] 查询设置失败: {e}")
        return None


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="设置 OpenSearch HTTP 行长度限制")
    parser.add_argument(
        "--length",
        type=str,
        default="16kb",
        help="HTTP 行长度限制（默认: 16kb）"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="只检查当前设置，不修改"
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("OpenSearch HTTP 行长度设置")
    print("=" * 80)
    
    # 检查当前设置
    current = check_current_setting()
    
    if args.check_only:
        print("\n[INFO] 仅检查模式，不修改设置")
    else:
        # 设置新值
        print(f"\n设置 http.max_initial_line_length = {args.length}...")
        success = set_http_line_length(args.length)
        
        if success:
            # 再次检查确认
            print("\n验证设置...")
            new_value = check_current_setting()
            if new_value and new_value != current:
                print(f"\n[OK] 设置成功！从 {current} 更新为 {new_value}")
            else:
                print(f"\n[WARNING] 设置可能未生效，当前值仍为 {current}")
