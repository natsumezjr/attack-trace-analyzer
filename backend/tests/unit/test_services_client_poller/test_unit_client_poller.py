from __future__ import annotations

import pytest


pytestmark = [pytest.mark.unit]


def test_update_poll_status_uses_nested_poll(monkeypatch, mock_opensearch_client):
    from app.services import client_poller

    monkeypatch.setattr(client_poller, "get_client", lambda: mock_opensearch_client)
    monkeypatch.setattr(client_poller, "utc_now_rfc3339", lambda: "2026-01-15T00:00:00Z")

    client_poller._update_poll_status("client-1", status="ok", last_error=None)

    mock_opensearch_client.update.assert_called_once_with(
        index=client_poller.INDEX_PATTERNS["CLIENT_REGISTRY"],
        id="client-1",
        body={
            "doc": {
                "poll": {
                    "last_seen": "2026-01-15T00:00:00Z",
                    "status": "ok",
                    "last_error": None,
                }
            }
        },
    )
