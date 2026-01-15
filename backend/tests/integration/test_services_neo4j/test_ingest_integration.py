from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.neo4j import models
from app.services.neo4j.ecs_ingest import _extract_dns_answer_ips, ecs_event_to_graph


def _fixtures_dir() -> Path:
    # backend/tests/integration/test_services_neo4j/* -> backend/tests/fixtures
    return Path(__file__).resolve().parents[2] / "fixtures"


def test_fixture_testexample_json_is_present_and_valid_json() -> None:
    fixture_path = _fixtures_dir() / "graph" / "testExample.json"
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) > 0


def test_extract_dns_answer_ips_supports_multiple_answer_shapes() -> None:
    event = {
        "dns": {
            "answers": [
                {"data": "8.8.8.8"},
                {"ip": "1.1.1.1"},
                "9.9.9.9",
            ],
            "resolved_ip": "4.4.4.4",
        }
    }
    ips = _extract_dns_answer_ips(event)
    assert ips == ["8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4"]


def test_ecs_event_to_graph_returns_empty_for_unknown_kind() -> None:
    nodes, edges = ecs_event_to_graph({"event": {"kind": "metric"}})
    assert nodes == []
    assert edges == []


def test_ecs_event_to_graph_authentication_creates_logon_edge() -> None:
    event = {
        "@timestamp": "2026-01-12T03:21:10.123Z",
        "event": {
            "id": "evt-auth-001",
            "kind": "event",
            "dataset": "hostlog.auth",
            "category": ["authentication"],
            "action": "user_login",
        },
        "host": {"id": "h-001", "name": "victim-01"},
        "user": {"name": "alice"},
        "source": {"ip": "10.0.0.8"},
    }
    nodes, edges = ecs_event_to_graph(event)

    assert {n.ntype for n in nodes} == {models.NodeType.HOST, models.NodeType.USER}
    assert len(edges) == 1

    edge = edges[0]
    assert edge.rtype == models.RelType.LOGON
    assert edge.props["event.id"] == "evt-auth-001"
    assert edge.props["event.kind"] == "event"
    assert edge.props["event.dataset"] == "hostlog.auth"


def test_ecs_event_to_graph_file_op_creates_uses_edge_with_op() -> None:
    event = {
        "@timestamp": "2026-01-12T03:21:10.123Z",
        "event": {
            "id": "evt-file-001",
            "kind": "event",
            "dataset": "hostbehavior.file",
            "category": ["file"],
            "action": "file_write",
        },
        "host": {"id": "h-001", "name": "victim-01"},
        "process": {
            "entity_id": "p-001",
            "pid": 123,
            "executable": "/usr/bin/cat",
        },
        "file": {"path": "/tmp/secret.txt"},
    }
    nodes, edges = ecs_event_to_graph(event)

    access_edges = [e for e in edges if e.rtype == models.RelType.FILE_ACCESS]
    assert len(access_edges) == 1
    assert access_edges[0].props.get("op") == "write"


def test_ecs_event_to_graph_dns_creates_resolved_edges() -> None:
    event = {
        "@timestamp": "2026-01-12T03:21:10.123Z",
        "event": {
            "id": "evt-dns-001",
            "kind": "event",
            "dataset": "netflow.dns",
            "category": ["network"],
            "action": "dns_query",
        },
        "host": {"id": "h-001", "name": "victim-01"},
        "source": {"ip": "10.0.0.8", "port": 5353},
        "destination": {"ip": "8.8.8.8", "port": 53},
        "network": {"transport": "udp"},
        "flow": {"id": "flow-001"},
        "dns": {
            "question": {"name": "example.com"},
            "answers": [{"data": "93.184.216.34"}],
        },
    }
    nodes, edges = ecs_event_to_graph(event)

    # Expected: Host, Domain, IP(answer) at minimum (v2 has no NetConn nodes).
    node_types = {n.ntype for n in nodes}
    assert models.NodeType.HOST in node_types
    assert models.NodeType.DOMAIN in node_types
    assert models.NodeType.IP in node_types

    rtypes = [e.rtype for e in edges]
    assert models.RelType.DNS_QUERY in rtypes
    assert models.RelType.RESOLVES_TO in rtypes


def test_ecs_event_to_graph_canonical_finding_dns_creates_alarm_dns_query_edge() -> None:
    event = {
        "@timestamp": "2026-01-12T03:25:05.000Z",
        "event": {
            "id": "calrt-001",
            "kind": "alert",
            "dataset": "finding.canonical",
            "category": ["network"],
            "type": ["info"],
            "action": "dns_tunnel_suspected",
            "severity": 70,
        },
        "host": {"id": "h-001", "name": "sensor-01"},
        "dns": {"question": {"name": "evil-c2.com", "type": "TXT"}},
        "custom": {"evidence": {"event_ids": ["evt-dns-001"]}},
        "rule": {"id": "R-DNS-001", "name": "DNS Tunnel Suspected", "ruleset": "suricata"},
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0011", "name": "Command and Control"},
            "technique": {"id": "T1071", "name": "Application Layer Protocol"},
        },
    }
    nodes, edges = ecs_event_to_graph(event)

    assert any(n.ntype == models.NodeType.DOMAIN for n in nodes)
    alarm_dns_edges = [e for e in edges if e.rtype == models.RelType.DNS_QUERY]
    assert len(alarm_dns_edges) == 1
    assert alarm_dns_edges[0].props.get("is_alarm") is True
    assert alarm_dns_edges[0].props.get("custom.evidence.event_ids") == ["evt-dns-001"]


def test_ecs_get_in_supports_dotted_fallback_for_event_kind() -> None:
    # ecs_ingest._get_in supports dotted field fallback; ensure ecs_event_to_graph
    # accepts that representation for required fields.
    event = {
        "event.kind": "event",
        "event.dataset": "hostlog.auth",
        "event.category": ["authentication"],
        "event.id": "evt-auth-002",
        "@timestamp": "2026-01-12T03:21:10.123Z",
        "host": {"id": "h-001"},
        "user": {"name": "alice"},
    }
    nodes, edges = ecs_event_to_graph(event)
    assert len(edges) == 1
    assert edges[0].rtype == models.RelType.LOGON
