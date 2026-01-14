from __future__ import annotations

import pytest

from app.services.graph import models


def test_build_uid_single_key_includes_key_name() -> None:
    uid = models.build_uid(models.NodeType.HOST, {"host.id": "h-001"})
    assert uid == "Host:host.id=h-001"


def test_parse_uid_accepts_explicit_kv_format() -> None:
    ntype, key = models.parse_uid("Host:host.id=h-001")
    assert ntype == models.NodeType.HOST
    assert key == {"host.id": "h-001"}


def test_parse_uid_accepts_short_form_using_node_unique_key() -> None:
    # Short form is supported by parse_uid() for convenience:
    # "Host:h-001" -> {"host.id": "h-001"} because host.id is the unique key for Host.
    ntype, key = models.parse_uid("Host:h-001")
    assert ntype == models.NodeType.HOST
    assert key == {"host.id": "h-001"}


def test_build_uid_multi_key_is_sorted_and_roundtrips() -> None:
    uid = models.build_uid(models.NodeType.USER, {"user.name": "alice", "host.id": "h-001"})
    assert uid == "User:host.id=h-001;user.name=alice"

    ntype, key = models.parse_uid(uid)
    assert ntype == models.NodeType.USER
    assert key == {"host.id": "h-001", "user.name": "alice"}


def test_graphnode_uid_uses_build_uid() -> None:
    node = models.GraphNode(models.NodeType.IP, key={"ip": "8.8.8.8"})
    assert node.uid == "IP:ip=8.8.8.8"


def test_graphnode_merged_props_prefers_existing_props_values() -> None:
    # NOTE: Current implementation uses dict.setdefault(), so if props already
    # contains the same key, it is NOT overridden by key fields.
    node = models.GraphNode(
        models.NodeType.HOST,
        key={"host.id": "h-001"},
        props={"host.id": "h-props", "host.name": "victim-01"},
    )
    merged = node.merged_props()
    assert merged["host.id"] == "h-props"
    assert merged["host.name"] == "victim-01"


def test_make_edge_valid_types_ok() -> None:
    host = models.host_node(host_id="h-001", host_name="victim-01")
    user = models.user_node(user_name="alice", host_id="h-001")
    edge = models.make_edge(user, host, models.RelType.LOGON, ts="2026-01-12T00:00:00Z")
    assert edge.rtype == models.RelType.LOGON
    assert edge.src_uid.startswith("User:")
    assert edge.dst_uid.startswith("Host:")
    assert edge.props["ts"] == "2026-01-12T00:00:00Z"
    assert edge.props["@timestamp"] == "2026-01-12T00:00:00Z"


def test_make_edge_invalid_types_raise() -> None:
    host_a = models.host_node(host_id="h-001")
    host_b = models.host_node(host_id="h-002")
    with pytest.raises(ValueError):
        _ = models.make_edge(host_a, host_b, models.RelType.LOGON)


def test_get_attack_tag_reads_nested_threat_tactic_name() -> None:
    edge = models.GraphEdge(
        src_uid="Host:host.id=h-001",
        dst_uid="Host:host.id=h-002",
        rtype=models.RelType.NET_CONNECT,
        props={"threat": {"tactic": {"name": "Execution"}}},
    )
    assert edge.get_attack_tag() == "Execution"
