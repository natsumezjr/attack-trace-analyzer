from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# ========== 全局Fixtures ==========

@pytest.fixture(scope="session")
def test_data_dir():
    """测试数据目录路径"""
    return Path(__file__).parent / "fixtures"


# ========== backend/tests/conftest.py -> backend/ ==========
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    # Ensure `import app...` works even when running the `pytest` entrypoint script
    # (e.g., `uv run pytest`), where sys.path[0] may point to the venv bin dir.
    sys.path.insert(0, str(BACKEND_ROOT))


def _env_flag(name: str, *, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def pytest_configure(config):
    """配置pytest标记"""
    config.addinivalue_line("markers", "unit: 单元测试（无外部依赖）")
    config.addinivalue_line("markers", "integration: 集成测试（需要外部服务）")
    config.addinivalue_line("markers", "e2e: 端到端测试（完整业务流程）")
    config.addinivalue_line("markers", "slow: 运行时间较长的测试")
    config.addinivalue_line("markers", "requires_opensearch: 需要OpenSearch")
    config.addinivalue_line("markers", "requires_neo4j: 需要Neo4j")
    config.addinivalue_line("markers", "requires_llm: 需要LLM服务")


def pytest_runtest_setup(item: pytest.Item) -> None:
    # Keep unit tests runnable on a developer machine without bringing up infra.
    if "requires_opensearch" in item.keywords and not _env_flag("RUN_OPENSEARCH_TESTS"):
        pytest.skip("Set RUN_OPENSEARCH_TESTS=1 to run OpenSearch-dependent tests.")
    if "requires_neo4j" in item.keywords and not _env_flag("RUN_NEO4J_TESTS", default=True):
        pytest.skip("Set RUN_NEO4J_TESTS=0 to skip Neo4j-dependent tests.")
    if "requires_llm" in item.keywords and not _env_flag("RUN_LLM_TESTS"):
        pytest.skip("Set RUN_LLM_TESTS=1 to run LLM-dependent tests.")
