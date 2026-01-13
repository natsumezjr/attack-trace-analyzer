from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# backend/tests/conftest.py -> backend/
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    # Ensure `import app...` works even when running the `pytest` entrypoint script
    # (e.g., `uv run pytest`), where sys.path[0] may point to the venv bin dir.
    sys.path.insert(0, str(BACKEND_ROOT))


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "y", "on"}


def pytest_runtest_setup(item: pytest.Item) -> None:
    # Keep unit tests runnable on a developer machine without bringing up infra.
    if "requires_opensearch" in item.keywords and not _env_flag("RUN_OPENSEARCH_TESTS"):
        raise pytest.SkipTest("Set RUN_OPENSEARCH_TESTS=1 to run OpenSearch-dependent tests.")
    if "requires_neo4j" in item.keywords and not _env_flag("RUN_NEO4J_TESTS"):
        raise pytest.SkipTest("Set RUN_NEO4J_TESTS=1 to run Neo4j-dependent tests.")
