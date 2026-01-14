#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""调试：查找 workflow ID"""
import sys
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.dirname(script_dir)
services_dir = os.path.dirname(scripts_dir)
app_dir = os.path.dirname(services_dir)
backend_dir = os.path.dirname(app_dir)

sys.path.insert(0, backend_dir)

from app.services.opensearch.client import get_client

if __name__ == '__main__':
    client = get_client()
    
    print("=" * 60)
    print("调试：查找 Workflow ID")
    print("=" * 60)
    
    # 查询所有workflow
    print("\n查询所有workflow...")
    try:
        workflow_resp = client.transport.perform_request(
            'POST',
            '/_plugins/_alerting/monitors/_search',
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "workflow"}},
                            {"term": {"workflow_type": "composite"}},
                            {"term": {"owner": "security_analytics"}}
                        ]
                    }
                },
                "size": 10
            }
        )
        
        hits = workflow_resp.get('hits', {}).get('hits', [])
        print(f"找到 {len(hits)} 个workflow")
        
        if hits:
            for i, hit in enumerate(hits, 1):
                workflow_id = hit.get('_id')
                workflow_source = hit.get('_source', {})
                print(f"\nWorkflow {i}:")
                print(f"  ID: {workflow_id}")
                print(f"  名称: {workflow_source.get('name', 'N/A')}")
                print(f"  类型: {workflow_source.get('type', 'N/A')}")
                print(f"  Workflow类型: {workflow_source.get('workflow_type', 'N/A')}")
                print(f"  所有者: {workflow_source.get('owner', 'N/A')}")
        else:
            print("\n未找到符合条件的workflow，尝试查询所有workflow...")
            
            # 查询所有workflow（不限制owner）
            all_workflow_resp = client.transport.perform_request(
                'POST',
                '/_plugins/_alerting/monitors/_search',
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"type": "workflow"}},
                                {"term": {"workflow_type": "composite"}}
                            ]
                        }
                    },
                    "size": 10
                }
            )
            
            all_hits = all_workflow_resp.get('hits', {}).get('hits', [])
            print(f"找到 {len(all_hits)} 个composite workflow（不限owner）")
            
            for i, hit in enumerate(all_hits, 1):
                workflow_id = hit.get('_id')
                workflow_source = hit.get('_source', {})
                print(f"\nWorkflow {i}:")
                print(f"  ID: {workflow_id}")
                print(f"  名称: {workflow_source.get('name', 'N/A')}")
                print(f"  所有者: {workflow_source.get('owner', 'N/A')}")
                
    except Exception as e:
        print(f"查询失败: {e}")
        import traceback
        traceback.print_exc()
