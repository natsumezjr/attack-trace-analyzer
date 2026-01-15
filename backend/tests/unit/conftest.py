"""
单元测试共享fixtures
所有单元测试使用mock，不连接外部服务
"""
from __future__ import annotations

from unittest.mock import MagicMock, Mock

import pytest


@pytest.fixture
def mock_opensearch_client():
    """模拟OpenSearch客户端"""
    client = MagicMock()
    client.indices = MagicMock()
    client.search = MagicMock(return_value={"hits": {"hits": [], "total": {"value": 0}}})
    client.index = MagicMock(return_value={"result": "created"})
    client.get = MagicMock(return_value={"_source": {}})
    client.exists = MagicMock(return_value=False)
    return client


@pytest.fixture
def mock_neo4j_session():
    """模拟Neo4j会话"""
    session = MagicMock()
    session.run = MagicMock(return_value=[])
    return session


@pytest.fixture
def mock_neo4j_driver():
    """模拟Neo4j驱动"""
    driver = MagicMock()
    driver.session = MagicMock(return_value=mock_neo4j_session())
    return driver


@pytest.fixture
def mock_llm_client():
    """模拟LLM客户端"""
    client = MagicMock()
    mock_response = Mock()
    mock_response.choices = [Mock(message=Mock(content="test response"))]
    client.chat.completions.create = MagicMock(return_value=mock_response)
    return client


@pytest.fixture
def sample_event():
    """示例事件数据"""
    return {
        "@timestamp": "2024-01-01T00:00:00Z",
        "event": {
            "id": "test-event-001",
            "kind": "event",
            "dataset": "falco",
        },
        "host": {
            "id": "test-host-001",
            "name": "test-host",
        },
        "process": {
            "entity_id": "test-process-001",
            "name": "test-process",
            "executable": "/bin/test",
        }
    }


@pytest.fixture
def sample_finding():
    """示例告警数据"""
    return {
        "@timestamp": "2024-01-01T00:00:00Z",
        "event": {
            "id": "test-finding-001",
            "kind": "alert",
            "dataset": "finding.raw",
        },
        "threat": {
            "technique": {
                "id": "T1078",
                "name": "Valid Accounts",
                "reference": "https://attack.mitre.org/techniques/T1078"
            }
        },
        "host": {
            "id": "test-host-001",
            "name": "test-host",
        },
        "custom": {
            "finding": {
                "stage": "raw",
                "providers": ["falco"]
            }
        }
    }
