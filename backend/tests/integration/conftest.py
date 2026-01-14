"""
集成测试共享fixtures
需要真实的外部服务（OpenSearch, Neo4j等）
"""
from __future__ import annotations

import os
from datetime import datetime

import pytest
from httpx import AsyncClient, ASGITransport


def _set_default_env(name: str, value: str) -> None:
    """设置默认环境变量"""
    if os.getenv(name, "").strip():
        return
    os.environ[name] = value


# 设置默认环境变量
_set_default_env("OPENSEARCH_NODE", "https://localhost:9200")
_set_default_env("OPENSEARCH_USERNAME", "admin")
_set_default_env("OPENSEARCH_PASSWORD", "OpenSearch@2024!Dev")
_set_default_env("NEO4J_URI", "bolt://localhost:7687")
_set_default_env("NEO4J_USERNAME", "neo4j")
_set_default_env("NEO4J_PASSWORD", "password")


# ========== OpenSearch Fixtures (从 opensearch/conftest.py 迁移) ==========

@pytest.fixture(scope="session")
def opensearch_client():
    """OpenSearch客户端（session-scoped）"""
    from app.services.opensearch.internal import get_client
    return get_client()


@pytest.fixture(scope="function")
def clean_test_indices(opensearch_client):
    """清理测试索引"""
    from app.services.opensearch.index import INDEX_PATTERNS, get_index_name

    today = datetime.now()
    test_indices = [
        get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today),
        get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today),
        get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today),
    ]

    for index_name in test_indices:
        try:
            if opensearch_client.indices.exists(index=index_name):
                opensearch_client.indices.delete(index=index_name)
        except Exception:
            # Best-effort cleanup: missing indices / auth issues shouldn't crash collection.
            pass

    yield


@pytest.fixture(scope="function")
def initialized_indices(clean_test_indices):
    """初始化所有索引"""
    from app.services.opensearch.internal import initialize_indices
    initialize_indices()
    yield


# ========== Neo4j Fixtures ==========

@pytest.fixture(scope="session")
def neo4j_driver():
    """Neo4j驱动（session-scoped）"""
    from app.services.neo4j.internal import get_driver
    return get_driver()


@pytest.fixture(scope="function")
def clean_neo4j_db(neo4j_driver):
    """清理Neo4j测试数据库"""
    with neo4j_driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    yield


# ========== API测试Fixtures ==========

@pytest.fixture(scope="function")
async def async_client():
    """FastAPI异步测试客户端"""
    from app.api.router import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
