"""
端到端测试共享fixtures
完整的业务流程测试环境
"""
from __future__ import annotations

import pytest


@pytest.fixture(scope="function")
def full_test_environment(initialized_indices, clean_neo4j_db):
    """完整测试环境（OpenSearch + Neo4j）

    这个fixture提供了一个完整的测试环境，包括：
    - 初始化的OpenSearch索引
    - 清理过的Neo4j数据库

    用于端到端测试，模拟完整的业务场景。
    """
    # 可以在这里初始化完整的攻击场景数据
    yield {
        "opensearch": initialized_indices,
        "neo4j": clean_neo4j_db,
    }
