#!/usr/bin/env python3
"""
测试 LLM 连接

直接测试 DeepSeek API 连接是否正常，不依赖 killchain 流程。

用法:
    docker compose exec python python scripts/test_llm_connection.py
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到 Python 路径
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.analyze.killchain_llm import create_llm_client


def test_llm_connection():
    """测试 LLM 连接"""
    print("=" * 60)
    print("LLM 连接测试")
    print("=" * 60)
    
    # 检查环境变量
    print("\n[1/4] 检查环境变量...")
    llm_provider = os.getenv("LLM_PROVIDER", "not_set")
    has_api_key = bool(os.getenv("DEEPSEEK_API_KEY"))
    api_key_preview = os.getenv("DEEPSEEK_API_KEY", "")[:20] + "..." if has_api_key else "None"
    
    print(f"  - LLM_PROVIDER: {llm_provider}")
    print(f"  - DEEPSEEK_API_KEY: {api_key_preview}")
    print(f"  - Has API Key: {has_api_key}")
    
    # 创建 LLM client
    print("\n[2/4] 创建 LLM client...")
    try:
        llm_client = create_llm_client()
        client_type = type(llm_client).__name__
        print(f"  ✓ Client 类型: {client_type}")
        
        if client_type == "MockChooser":
            print("  ⚠️  使用 MockChooser（mock 模式）")
            print("  - 原因: LLM_PROVIDER=mock 或 DEEPSEEK_API_KEY 未设置")
        elif client_type == "LLMChooser":
            print("  ✓ 使用 LLMChooser（真实 LLM 模式）")
            if hasattr(llm_client, "chat_complete"):
                if llm_client.chat_complete is None:
                    print("  ⚠️  chat_complete 为 None")
                else:
                    print("  ✓ chat_complete 已设置")
        else:
            print(f"  ⚠️  未知的 client 类型: {client_type}")
    except Exception as e:
        print(f"  ❌ 创建失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # 测试简单的 choose 调用
    print("\n[3/4] 测试 choose 方法...")
    test_payload = {
        "segments": [
            {
                "seg_idx": 0,
                "state": "Execution",
                "t_start": 1000.0,
                "t_end": 2000.0,
                "anchor_in_uid": "Process:p-001",
                "anchor_out_uid": "Process:p-002",
                "abnormal_edge_summaries": []
            }
        ],
        "pairs": [
            {
                "pair_idx": 0,
                "from_seg_idx": 0,
                "to_seg_idx": 1,
                "src_anchor": "Process:p-001",
                "dst_anchor": "Process:p-002",
                "t_min": 1500.0,
                "t_max": 2500.0,
                "candidates": [
                    {
                        "path_id": "p-test-001",
                        "steps": [
                            {
                                "ts": 1800.0,
                                "src_uid": "Process:p-001",
                                "rel": "SPAWN",
                                "dst_uid": "Process:p-002",
                                "key_props": {}
                            }
                        ]
                    }
                ]
            }
        ],
        "constraints": {}
    }
    
    try:
        print(f"  - 测试 payload: {len(test_payload.get('pairs', []))} pairs")
        result = llm_client.choose(test_payload)
        print(f"  ✓ choose 方法调用成功")
        print(f"  - 返回类型: {type(result)}")
        print(f"  - chosen_path_ids: {result.get('chosen_path_ids', [])}")
        print(f"  - explanation: {result.get('explanation', '')[:100]}...")
        
        if client_type == "LLMChooser" and result.get('explanation', '').startswith('fallback'):
            print("  ⚠️  返回了 fallback 结果，可能是 API 调用失败")
        elif client_type == "MockChooser":
            print("  ✓ Mock 模式正常工作")
        else:
            print("  ✓ LLM 调用成功")
            
    except Exception as e:
        print(f"  ❌ choose 方法调用失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # 测试空 pairs 的情况
    print("\n[4/4] 测试空 pairs 的情况...")
    empty_payload = {
        "segments": [
            {
                "seg_idx": 0,
                "state": "Execution",
                "t_start": 1000.0,
                "t_end": 2000.0,
                "anchor_in_uid": "Process:p-001",
                "anchor_out_uid": "Process:p-002",
                "abnormal_edge_summaries": []
            }
        ],
        "pairs": [],
        "constraints": {}
    }
    
    try:
        result = llm_client.choose(empty_payload)
        print(f"  ✓ 空 pairs 处理成功")
        print(f"  - chosen_path_ids: {result.get('chosen_path_ids', [])}")
        print(f"  - explanation: {result.get('explanation', '')[:100]}...")
    except Exception as e:
        print(f"  ❌ 空 pairs 处理失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 60)
    print("测试完成！")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = test_llm_connection()
    sys.exit(0 if success else 1)
