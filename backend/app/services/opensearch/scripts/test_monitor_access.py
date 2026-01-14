#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 monitor 访问权限

用途：详细测试对 monitor 配置索引的访问权限

使用方法：
    python test_monitor_access.py --workflow-id <workflow_id>
"""

import sys
import os
import argparse

# 添加项目路径
script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)  # opensearch/
services_dir = os.path.dirname(scripts_dir)  # services/
app_dir = os.path.dirname(services_dir)  # app/
backend_dir = os.path.dirname(app_dir)  # backend/

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client, reset_client


def test_index_access(client, index_name: str):
    """测试对索引的访问权限"""
    try:
        # 尝试搜索索引
        resp = client.search(index=index_name, body={"query": {"match_all": {}}, "size": 1})
        return True, f"✓ 可以搜索索引 {index_name}"
    except Exception as e:
        error_msg = str(e)
        if '403' in error_msg or 'forbidden' in error_msg.lower():
            return False, f"✗ 权限被拒绝（403）: {index_name}"
        elif '404' in error_msg or 'not found' in error_msg.lower():
            return False, f"⚠ 索引不存在（404）: {index_name}"
        else:
            return False, f"✗ 访问失败: {index_name} - {error_msg}"


def test_get_document(client, index_name: str, doc_id: str):
    """测试获取文档的权限"""
    try:
        resp = client.get(index=index_name, id=doc_id)
        return True, f"✓ 可以读取文档 {doc_id} 从 {index_name}"
    except Exception as e:
        error_msg = str(e)
        if '403' in error_msg or 'forbidden' in error_msg.lower():
            return False, f"✗ 权限被拒绝（403）: 无法读取 {doc_id}"
        elif '404' in error_msg:
            return False, f"⚠ 文档不存在（404）: {doc_id}"
        else:
            return False, f"✗ 读取失败: {error_msg}"


def main():
    parser = argparse.ArgumentParser(description='测试monitor访问权限')
    parser.add_argument('--workflow-id', default='TeBJt5sBYd8aacU-nv8J', help='workflow ID（默认: TeBJt5sBYd8aacU-nv8J）')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Monitor 访问权限测试")
    print("=" * 60)
    
    reset_client()
    client = get_client()
    
    workflow_id = args.workflow_id
    
    # 测试1: 直接访问monitor API
    print(f"\n1. 测试 GET /_plugins/_alerting/monitors/{workflow_id}:")
    try:
        resp = client.transport.perform_request('GET', f'/_plugins/_alerting/monitors/{workflow_id}')
        print(f"   ✓ GET monitor API 成功")
        print(f"   响应keys: {list(resp.keys())}")
    except Exception as e:
        error_msg = str(e)
        print(f"   ✗ GET monitor API 失败: {error_msg}")
    
    # 测试2: 测试对各个索引的访问
    print(f"\n2. 测试对alerting系统索引的访问:")
    indices_to_test = [
        ".opendistro-alerting-config",
        ".opensearch-alerting-config",
        ".opendistro-alerting-alerts"
    ]
    
    for idx in indices_to_test:
        success, message = test_index_access(client, idx)
        print(f"   {message}")
    
    # 测试3: 尝试直接从索引读取monitor文档
    print(f"\n3. 尝试直接从索引读取monitor文档:")
    # monitor文档通常存储在 .opendistro-alerting-config 或 .opensearch-alerting-config
    config_indices = [".opendistro-alerting-config", ".opensearch-alerting-config"]
    
    for idx in config_indices:
        success, message = test_get_document(client, idx, workflow_id)
        if success:
            print(f"   {message}")
            break
        else:
            print(f"   {message}")
    
    # 测试4: 搜索monitor文档（尝试多种查询方式）
    print(f"\n4. 搜索monitor文档:")
    for idx in config_indices:
        try:
            # 方式1: 通过_id查询（使用term查询_id字段）
            resp = client.search(
                index=idx,
                body={
                    "query": {
                        "term": {"_id": workflow_id}
                    },
                    "size": 1
                }
            )
            hits = resp.get('hits', {}).get('hits', [])
            if hits:
                print(f"   ✓ 在 {idx} 中找到monitor文档（通过_id）")
                doc = hits[0].get('_source', {})
                print(f"      文档keys: {list(doc.keys())[:10]}")
                break
            
            # 方式2: 通过name查询（查找包含detector名称的monitor）
            resp = client.search(
                index=idx,
                body={
                    "query": {
                        "match": {"name": "ecs-events-detector"}
                    },
                    "size": 10
                }
            )
            hits = resp.get('hits', {}).get('hits', [])
            if hits:
                print(f"   ✓ 在 {idx} 中找到 {len(hits)} 个相关文档（通过name）")
                for hit in hits[:3]:
                    hit_id = hit.get('_id')
                    hit_source = hit.get('_source', {})
                    hit_name = hit_source.get('name', 'N/A')
                    hit_type = hit_source.get('type', 'N/A')
                    print(f"      - ID: {hit_id}, name: {hit_name}, type: {hit_type}")
                break
            
            # 方式3: 列出所有文档（查看索引中实际存储了什么）
            resp = client.search(
                index=idx,
                body={
                    "query": {"match_all": {}},
                    "size": 20
                }
            )
            hits = resp.get('hits', {}).get('hits', [])
            if hits:
                print(f"   ⚠ 在 {idx} 中找到 {len(hits)} 个文档，但workflow_id不匹配")
                print(f"      前5个文档的详细信息:")
                for hit in hits[:5]:
                    hit_id = hit.get('_id')
                    hit_source = hit.get('_source', {})
                    hit_name = hit_source.get('name', 'N/A')
                    hit_type = hit_source.get('type', hit_source.get('monitor_type', 'N/A'))
                    hit_owner = hit_source.get('owner', 'N/A')
                    print(f"      - ID: {hit_id}")
                    print(f"        name: {hit_name}, type: {hit_type}, owner: {hit_owner}")
                    # 检查是否包含workflow相关字段
                    if 'workflow' in str(hit_source).lower() or 'composite' in str(hit_type).lower():
                        print(f"        ⚠ 可能是workflow/composite monitor")
                # 检查是否有workflow_id匹配的文档
                matching_hits = [h for h in hits if h.get('_id') == workflow_id]
                if matching_hits:
                    print(f"   ✓ 找到匹配的workflow_id文档！")
                else:
                    print(f"   ⚠ workflow_id {workflow_id} 不在前{len(hits)}个文档中")
            else:
                print(f"   ⚠ 在 {idx} 中未找到任何文档")
        except Exception as e:
            print(f"   ✗ 搜索 {idx} 失败: {e}")
    
    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
