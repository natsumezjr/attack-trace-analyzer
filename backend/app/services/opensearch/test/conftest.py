# -*- coding: utf-8 -*-
"""
pytest 配置文件
提供测试用的 fixture 和配置
"""

import os
import sys
import pytest
from pathlib import Path
from typing import Generator
from datetime import datetime

# 添加父目录到路径，以便导入 opensearch 模块
test_dir = Path(__file__).parent
parent_dir = test_dir.parent
sys.path.insert(0, str(parent_dir))

# 设置测试环境变量（如果未设置）
if not os.getenv("OPENSEARCH_NODE"):
    os.environ["OPENSEARCH_NODE"] = "https://localhost:9200"
if not os.getenv("OPENSEARCH_USERNAME"):
    os.environ["OPENSEARCH_USERNAME"] = "admin"
if not os.getenv("OPENSEARCH_PASSWORD"):
    os.environ["OPENSEARCH_PASSWORD"] = "OpenSearch@2024!Dev"


@pytest.fixture(scope="session")
def opensearch_client():
    """
    获取 OpenSearch 客户端（会话级别，所有测试共享）
    """
    from .. import get_client
    return get_client()


@pytest.fixture(scope="function")
def clean_test_indices(opensearch_client):
    """
    清理测试索引（每个测试函数执行前后）
    """
    from ..index import INDEX_PATTERNS, get_index_name
    
    today = datetime.now()
    test_indices = [
        get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today),
        get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today),
        get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today),
        get_index_name(INDEX_PATTERNS["ATTACK_CHAINS"], today),
    ]
    
    # 测试前清理
    for index_name in test_indices:
        try:
            if opensearch_client.indices.exists(index=index_name):
                opensearch_client.indices.delete(index=index_name)
        except Exception:
            pass
    
    yield
    
    # 测试后清理（可选，保留数据用于调试）
    # for index_name in test_indices:
    #     try:
    #         if opensearch_client.indices.exists(index=index_name):
    #             opensearch_client.indices.delete(index=index_name)
    #     except Exception:
    #         pass


@pytest.fixture(scope="function")
def initialized_indices(clean_test_indices):
    """
    初始化所有测试需要的索引
    """
    from .. import initialize_indices
    initialize_indices()
    yield
    # 清理在 clean_test_indices 中处理
