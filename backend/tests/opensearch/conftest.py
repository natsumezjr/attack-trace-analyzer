from __future__ import annotations

import os
from datetime import datetime

import pytest

from app.services.opensearch.internal import get_client, initialize_indices
from app.services.opensearch.index import INDEX_PATTERNS, get_index_name


def _set_default_env(name: str, value: str) -> None:
    if os.getenv(name, "").strip():
        return
    os.environ[name] = value


# Keep the defaults aligned with backend/.env.example and the local compose setup.
_set_default_env("OPENSEARCH_NODE", "https://localhost:9200")
_set_default_env("OPENSEARCH_USERNAME", "admin")
_set_default_env("OPENSEARCH_PASSWORD", "OpenSearch@2024!Dev")


@pytest.fixture(scope="session")
def opensearch_client():
    """OpenSearch client (session-scoped)."""
    return get_client()


@pytest.fixture(scope="function")
def clean_test_indices(opensearch_client):
    """Clean date-based test indices before each test."""
    today = datetime.now()
    test_indices = [
        get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today),
        get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today),
        get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today),
        get_index_name(INDEX_PATTERNS["ATTACK_CHAINS"], today),
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
    """Initialize all indices required by tests."""
    initialize_indices()
    yield
