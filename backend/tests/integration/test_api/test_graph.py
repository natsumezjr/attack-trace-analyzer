from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from app.services.neo4j import db as graph_db
from app.services.neo4j.models import RelType


def _fixtures_dir() -> Path:
    # backend/tests/integration/test_api/* -> backend/tests/fixtures
    return Path(__file__).resolve().parents[2] / "fixtures"


def _load_edges_in_window_rows() -> list[dict[str, Any]]:
    # 读取用于模拟 Neo4j 查询结果的测试数据（行结构与 _fetch_edges_in_window 返回保持一致）。
    fixture_path = _fixtures_dir() / "graph" / "edges_in_window_rows.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))


@contextmanager
def _dummy_session() -> Iterator[object]:
    # 伪造 session，避免单测触发真实 Neo4j 连接。
    yield object()


def test_edges_in_window_fixture_rows_present() -> None:
    # 基础校验：fixture 文件存在且行结构包含必要字段，避免误写导致后续测试失真。
    rows = _load_edges_in_window_rows()
    assert isinstance(rows, list)
    assert len(rows) >= 2
    for row in rows:
        assert "rtype" in row
        assert "rprops" in row
        assert "src_labels" in row
        assert "src_props" in row
        assert "dst_labels" in row
        assert "dst_props" in row


def test_get_edges_in_window_maps_rows_to_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    # 验证从“行结构”到 GraphEdge 的映射逻辑，不依赖数据库。
    rows = _load_edges_in_window_rows()

    def fake_execute_read(session, func, t_min, t_max, allowed_reltypes, only_alarm):
        return rows

    monkeypatch.setattr(graph_db, "_get_session", lambda: _dummy_session())
    monkeypatch.setattr(graph_db, "_execute_read", fake_execute_read)

    edges = graph_db.get_edges_in_window(t_min=0.0, t_max=9999999999.0)

    # 不依赖顺序：按 event.id 建索引，验证特定边的类型与端点映射。
    by_event_id = {
        edge.props.get("event.id"): edge
        for edge in edges
        if isinstance(edge.props, dict) and edge.props.get("event.id")
    }

    assert len(edges) == len(rows)
    assert "evt-logon-001" in by_event_id
    assert "evt-net-001" in by_event_id
    assert "evt-dns-001" in by_event_id

    logon = by_event_id["evt-logon-001"]
    assert logon.rtype == RelType.LOGON
    assert logon.src_uid == "User:user.id=u-001"
    assert logon.dst_uid == "Host:host.id=h-001"

    net = by_event_id["evt-net-001"]
    assert net.rtype == RelType.NET_CONNECT
    assert net.src_uid == "Process:process.entity_id=p-001-c"
    assert net.dst_uid == "IP:ip=93.184.216.1"

    dns = by_event_id["evt-dns-001"]
    assert dns.rtype == RelType.DNS_QUERY
    assert dns.src_uid == "Process:process.entity_id=p-001-c"
    assert dns.dst_uid == "Domain:domain.name=evil-01.example"


def test_get_edges_in_window_forwards_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    # 确认过滤参数会正确透传给底层查询函数。
    rows = _load_edges_in_window_rows()
    captured: dict[str, Any] = {}

    def fake_execute_read(session, func, t_min, t_max, allowed_reltypes, only_alarm):
        captured["t_min"] = t_min
        captured["t_max"] = t_max
        captured["allowed"] = allowed_reltypes
        captured["only_alarm"] = only_alarm
        return rows

    monkeypatch.setattr(graph_db, "_get_session", lambda: _dummy_session())
    monkeypatch.setattr(graph_db, "_execute_read", fake_execute_read)

    edges = graph_db.get_edges_in_window(
        t_min=10.0,
        t_max=20.0,
        allowed_reltypes=["NET_CONNECT"],
        only_alarm=True,
    )

    assert captured["t_min"] == 10.0
    assert captured["t_max"] == 20.0
    assert captured["allowed"] == ["NET_CONNECT"]
    assert captured["only_alarm"] is True
    assert len(edges) == len(rows)


def test_get_graph_for_frontend_returns_nodes_and_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    node_rows = [
        {"labels": ["Host"], "props": {"host.id": "h-001", "host.name": "alpha"}},
        {"labels": ["Process"], "props": {"process.entity_id": "p-001", "process.name": "proc"}},
    ]
    edge_rows = [
        {
            "rtype": "RUNS_ON",
            "rprops": {"event.id": "evt-001"},
            "src_labels": ["Process"],
            "src_props": {"process.entity_id": "p-001"},
            "dst_labels": ["Host"],
            "dst_props": {"host.id": "h-001"},
        }
    ]

    def fake_execute_read(session, func, *args, **kwargs):
        if func == graph_db._fetch_all_nodes:
            return node_rows
        if func == graph_db._fetch_all_edges:
            return edge_rows
        raise AssertionError("unexpected query function")

    monkeypatch.setattr(graph_db, "ensure_schema", lambda: None)
    monkeypatch.setattr(graph_db, "_get_session", lambda: _dummy_session())
    monkeypatch.setattr(graph_db, "_execute_read", fake_execute_read)

    payload = graph_db.get_graph_for_frontend()

    assert "data" in payload
    assert payload["behaviors"] == ["drag-canvas", "zoom-canvas", "drag-element"]

    nodes = payload["data"]["nodes"]
    edges = payload["data"]["edges"]

    assert len(nodes) == 2
    assert len(edges) == 1

    host_node = next(node for node in nodes if node["ntype"] == "Host")
    process_node = next(node for node in nodes if node["ntype"] == "Process")

    assert host_node["id"] == "Host:host.id=h-001"
    assert host_node["type"] == "image"
    assert host_node["style"]["src"] == "host"

    assert process_node["id"] == "Process:process.entity_id=p-001"
    assert process_node["type"] == "image"
    assert process_node["style"]["src"] == "process"

    edge = edges[0]
    assert edge["id"] == "edge-1"
    assert edge["type"] == "RUNS_ON"
    assert edge["source"] == process_node["id"]
    assert edge["target"] == host_node["id"]
