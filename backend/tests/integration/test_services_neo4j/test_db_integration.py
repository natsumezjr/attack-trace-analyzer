from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.services.neo4j import db as graph_db
from app.services.neo4j import ingest as graph_ingest


def _fixtures_dir() -> Path:
    # backend/tests/integration/test_services_neo4j/* -> backend/tests/fixtures
    return Path(__file__).resolve().parents[2] / "fixtures"


def _load_fixture_events() -> list[dict[str, Any]]:
    fixture_path = _fixtures_dir() / "graph" / "testExample.json"
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def _get_in(event: dict[str, Any], path: list[str]) -> Any | None:
    cur: Any = event
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            cur = None
            break
        cur = cur[key]
    if cur is not None:
        return cur
    dotted = ".".join(path)
    return event.get(dotted)


def _event_kind(event: dict[str, Any]) -> str | None:
    kind = event.get("event", {}).get("kind")
    if isinstance(kind, str) and kind:
        return kind
    kind = event.get("event.kind")
    return kind if isinstance(kind, str) and kind else None


def _event_dataset(event: dict[str, Any]) -> str | None:
    dataset = event.get("event", {}).get("dataset")
    if isinstance(dataset, str) and dataset:
        return dataset
    dataset = event.get("event.dataset")
    return dataset if isinstance(dataset, str) and dataset else None


def _event_id(event: dict[str, Any]) -> str | None:
    eid = event.get("event", {}).get("id")
    if isinstance(eid, str) and eid:
        return eid
    eid = event.get("event.id")
    return eid if isinstance(eid, str) and eid else None


def _eligible_event_ids(events: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for event in events:
        kind = _event_kind(event)
        dataset = _event_dataset(event) or ""
        if kind == "event" or (kind == "alert" and dataset == "finding.canonical"):
            eid = _event_id(event)
            if eid:
                ids.append(eid)
    return ids


def _canonical_event_ids(events: list[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for event in events:
        if _event_kind(event) == "alert" and _event_dataset(event) == "finding.canonical":
            eid = _event_id(event)
            if eid:
                ids.add(eid)
    return ids


def _delete_edges_by_event_ids(event_ids: list[str]) -> None:
    if not event_ids:
        return
    with graph_db._get_session() as session:
        session.run(
            "MATCH ()-[r]->() WHERE r.`event.id` IN $ids DELETE r",
            ids=event_ids,
        )


def _collect_host_ids(events: list[dict[str, Any]]) -> set[str]:
    host_ids: set[str] = set()
    for event in events:
        host_id = _get_in(event, ["host", "id"])
        if isinstance(host_id, str) and host_id:
            host_ids.add(host_id)
    return host_ids


def _collect_user_ids(events: list[dict[str, Any]]) -> set[str]:
    user_ids: set[str] = set()
    for event in events:
        user_id = _get_in(event, ["user", "id"])
        if isinstance(user_id, str) and user_id:
            user_ids.add(user_id)
    return user_ids


def _delete_nodes_by_host_and_user(
    host_ids: set[str],
    user_ids: set[str],
) -> None:
    if not host_ids and not user_ids:
        return
    with graph_db._get_session() as session:
        if user_ids:
            session.run(
                "MATCH (n:User) WHERE n.`user.id` IN $user_ids DETACH DELETE n",
                user_ids=list(user_ids),
            )
        if host_ids:
            session.run(
                "MATCH (n:User) WHERE n.`host.id` IN $host_ids DETACH DELETE n",
                host_ids=list(host_ids),
            )
            session.run(
                "MATCH (n:Host) WHERE n.`host.id` IN $host_ids DETACH DELETE n",
                host_ids=list(host_ids),
            )
            session.run(
                "MATCH (n:Process) WHERE n.`host.id` IN $host_ids DETACH DELETE n",
                host_ids=list(host_ids),
            )
            session.run(
                "MATCH (n:File) WHERE n.`host.id` IN $host_ids DETACH DELETE n",
                host_ids=list(host_ids),
            )


def _keep_test_data() -> bool:
    raw = str((__import__("os").getenv("KEEP_NEO4J_TEST_DATA", "") or "")).strip().lower()
    if not raw:
        return True
    return raw in {"1", "true", "yes", "y", "on"}


@pytest.mark.requires_neo4j
def test_ingest_fixture_events_into_neo4j() -> None:
    events = _load_fixture_events()
    eligible_ids = _eligible_event_ids(events)
    canonical_ids = _canonical_event_ids(events)
    host_ids = _collect_host_ids(events)
    user_ids = _collect_user_ids(events)
    keep_data = _keep_test_data()

    assert events
    assert eligible_ids
    assert canonical_ids

    _delete_edges_by_event_ids(eligible_ids)
    _delete_nodes_by_host_and_user(host_ids, user_ids)

    try:
        _, edge_count = graph_ingest.ingest_ecs_events(events)
        assert edge_count > 0

        with graph_db._get_session() as session:
            records = list(
                session.run(
                    "MATCH ()-[r]->() "
                    "WHERE r.`event.id` IN $ids "
                    "RETURN r.`event.id` AS eid",
                    ids=eligible_ids,
                )
            )
        inserted_ids = {record["eid"] for record in records if record.get("eid")}

        assert inserted_ids
        assert inserted_ids.issubset(set(eligible_ids))
        assert inserted_ids.intersection(canonical_ids)
    finally:
        if not keep_data:
            _delete_edges_by_event_ids(eligible_ids)
            _delete_nodes_by_host_and_user(host_ids, user_ids)
        graph_db.close()
