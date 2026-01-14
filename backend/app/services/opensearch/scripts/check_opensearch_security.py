#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查 OpenSearch 安全插件状态

用途：检测 OpenSearch 是否启用了安全插件（通过尝试 HTTP 和 HTTPS 连接）

使用方法：
    python check_opensearch_security.py
"""

import sys
import os
import requests
from urllib.parse import urlparse

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)


def test_connection(url: str, use_auth: bool = False):
    """测试连接"""
    try:
        kwargs = {
            "timeout": 5,
            "verify": False
        }
        if use_auth:
            kwargs["auth"] = (
                os.getenv("OPENSEARCH_USERNAME", "admin"),
                os.getenv("OPENSEARCH_PASSWORD", "OpenSearch@2024!Dev")
            )
        
        resp = requests.get(url, **kwargs)
        if resp.status_code == 200:
            return True, resp.json(), None
        else:
            return False, None, f"HTTP {resp.status_code}"
    except requests.exceptions.SSLError as e:
        return False, None, f"SSL错误: {e}"
    except requests.exceptions.ConnectionError as e:
        return False, None, f"连接错误: {e}"
    except Exception as e:
        return False, None, f"其他错误: {e}"


def main():
    print("=" * 60)
    print("检查 OpenSearch 安全插件状态")
    print("=" * 60)
    
    # 测试 HTTP（无认证）
    print("\n1. 测试 HTTP 连接（无认证）...")
    print("-" * 60)
    success, data, error = test_connection("http://localhost:9200", use_auth=False)
    if success:
        print("[OK] HTTP 连接成功（安全插件可能已禁用）")
        print(f"   集群名称: {data.get('cluster_name', 'N/A')}")
        print(f"   OpenSearch 版本: {data.get('version', {}).get('number', 'N/A')}")
        http_works = True
    else:
        print(f"[X] HTTP 连接失败: {error}")
        http_works = False
    
    # 测试 HTTPS（无认证）
    print("\n2. 测试 HTTPS 连接（无认证）...")
    print("-" * 60)
    success, data, error = test_connection("https://localhost:9200", use_auth=False)
    if success:
        print("[OK] HTTPS 连接成功（安全插件可能已禁用，但支持 HTTPS）")
        print(f"   集群名称: {data.get('cluster_name', 'N/A')}")
        print(f"   OpenSearch 版本: {data.get('version', {}).get('number', 'N/A')}")
        https_works_no_auth = True
    else:
        print(f"[X] HTTPS 连接失败: {error}")
        https_works_no_auth = False
    
    # 测试 HTTPS（有认证）
    print("\n3. 测试 HTTPS 连接（有认证）...")
    print("-" * 60)
    success, data, error = test_connection("https://localhost:9200", use_auth=True)
    if success:
        print("[OK] HTTPS + 认证连接成功（安全插件已启用）")
        print(f"   集群名称: {data.get('cluster_name', 'N/A')}")
        print(f"   OpenSearch 版本: {data.get('version', {}).get('number', 'N/A')}")
        https_works_auth = True
    else:
        print(f"[X] HTTPS + 认证连接失败: {error}")
        https_works_auth = False
    
    # 总结
    print("\n" + "=" * 60)
    print("总结")
    print("=" * 60)
    
    if http_works and not https_works_auth:
        print("[结论] 安全插件已禁用，应使用 HTTP（无认证）")
        print("[建议] 设置环境变量: OPENSEARCH_NODE=http://localhost:9200")
    elif https_works_auth:
        print("[结论] 安全插件已启用，应使用 HTTPS + 认证")
        print("[建议] 设置环境变量: OPENSEARCH_NODE=https://localhost:9200")
        print("[建议] 设置环境变量: OPENSEARCH_USERNAME=admin")
        print("[建议] 设置环境变量: OPENSEARCH_PASSWORD=你的密码")
    elif http_works:
        print("[结论] HTTP 可用，但 HTTPS 需要认证（安全插件可能部分启用）")
        print("[建议] 使用 HTTP: OPENSEARCH_NODE=http://localhost:9200")
    else:
        print("[结论] 无法确定，OpenSearch 可能未运行")
        print("[建议] 检查 OpenSearch 服务是否启动")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
