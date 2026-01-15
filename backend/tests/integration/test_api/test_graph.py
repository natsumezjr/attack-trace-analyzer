from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from app.services.neo4j import db as graph_db
from app.services.neo4j.models import RelType

pytestmark = pytest.mark.integration


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


# ========== API Routes Tests ==========


class TestGraphQueryAPI:
    """测试 /api/v1/graph/query API endpoint"""

    @pytest.mark.asyncio
    async def test_alarm_edges_action(self, async_client, monkeypatch: pytest.MonkeyPatch):
        """测试 alarm_edges action 返回告警边"""
        # Mock graph API responses
        mock_edges = [
            type("MockEdge", (), {
                "src_uid": "Process:process.entity_id=p-001",
                "dst_uid": "IP:ip=93.184.216.1",
                "rtype": type("MockRelType", (), {"value": "NET_CONNECT"})(),
                "props": {"event.id": "evt-001"},
            })(),
        ]
        mock_node = type("MockNode", (), {
            "uid": "Process:process.entity_id=p-001",
            "ntype": type("MockNodeType", (), {"value": "Process"})(),
            "key": {"process.entity_id": "p-001"},
            "props": {"process.name": "test"},
        })()

        def mock_get_alarm_edges():
            return mock_edges

        def mock_get_node(uid):
            return mock_node if uid == "Process:process.entity_id=p-001" else None

        monkeypatch.setattr("app.api.routes.graph.graph_api.get_alarm_edges", mock_get_alarm_edges)
        monkeypatch.setattr("app.api.routes.graph.graph_api.get_node", mock_get_node)

        response = await async_client.post(
            "/api/v1/graph/query",
            json={"action": "alarm_edges"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "edges" in data
        assert "nodes" in data
        assert "server_time" in data
        assert len(data["edges"]) == 1
        assert data["edges"][0]["rtype"] == "NET_CONNECT"

    @pytest.mark.asyncio
    async def test_edges_in_window_action_success(self, async_client, monkeypatch: pytest.MonkeyPatch):
        """测试 edges_in_window action 成功场景
        此测试会验证 get_edges_in_window 使用正确的关键字参数
        """
        mock_edges = [
            type("MockEdge", (), {
                "src_uid": "Process:process.entity_id=p-001",
                "dst_uid": "IP:ip=93.184.216.1",
                "rtype": type("MockRelType", (), {"value": "NET_CONNECT"})(),
                "props": {"event.id": "evt-001"},
            })(),
        ]

        call_captured = {}

        def mock_get_edges_in_window(*, t_min, t_max, allowed_reltypes=None, only_alarm=False):
            # 捕获调用参数，验证使用了关键字参数
            call_captured["t_min"] = t_min
            call_captured["t_max"] = t_max
            call_captured["allowed_reltypes"] = allowed_reltypes
            call_captured["only_alarm"] = only_alarm
            return mock_edges

        def mock_get_node(uid):
            return None

        monkeypatch.setattr("app.api.routes.graph.graph_api.get_edges_in_window", mock_get_edges_in_window)
        monkeypatch.setattr("app.api.routes.graph.graph_api.get_node", mock_get_node)

        response = await async_client.post(
            "/api/v1/graph/query",
            json={
                "action": "edges_in_window",
                "start_ts": "2024-01-01T00:00:00Z",
                "end_ts": "2024-01-02T00:00:00Z",
            },
        )

        # 验证 API 调用成功
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "edges" in data

        # 验证底层函数被正确调用（使用关键字参数）
        assert "t_min" in call_captured
        assert "t_max" in call_captured
        assert call_captured["t_min"] > 0
        assert call_captured["t_max"] > call_captured["t_min"]

    @pytest.mark.asyncio
    async def test_edges_in_window_missing_timestamps(self, async_client):
        """测试 edges_in_window action 缺少时间参数"""
        response = await async_client.post(
            "/api/v1/graph/query",
            json={"action": "edges_in_window"},
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "BAD_REQUEST"
        assert "start_ts and end_ts are required" in data["error"]["message"]

    @pytest.mark.asyncio
    async def test_edges_in_window_with_filters(self, async_client, monkeypatch: pytest.MonkeyPatch):
        """测试 edges_in_window action 带过滤参数"""
        def mock_get_edges_in_window(*, t_min, t_max, allowed_reltypes=None, only_alarm=False):
            # 验证过滤参数正确传递
            assert allowed_reltypes == ["NET_CONNECT", "DNS_QUERY"]
            assert only_alarm is True
            return []

        def mock_get_node(uid):
            return None

        monkeypatch.setattr("app.api.routes.graph.graph_api.get_edges_in_window", mock_get_edges_in_window)
        monkeypatch.setattr("app.api.routes.graph.graph_api.get_node", mock_get_node)

        response = await async_client.post(
            "/api/v1/graph/query",
            json={
                "action": "edges_in_window",
                "start_ts": "2024-01-01T00:00:00Z",
                "end_ts": "2024-01-02T00:00:00Z",
                "allowed_reltypes": ["NET_CONNECT", "DNS_QUERY"],
                "only_alarm": True,
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_analysis_edges_by_task_action(self, async_client, monkeypatch: pytest.MonkeyPatch):
        """测试 analysis_edges_by_task action"""
        def mock_get_edges_by_task_id(*, task_id, only_path=False):
            assert task_id == "task-123"
            assert only_path is True
            return []

        def mock_get_node(uid):
            return None

        monkeypatch.setattr("app.api.routes.graph.graph_api.get_edges_by_task_id", mock_get_edges_by_task_id)
        monkeypatch.setattr("app.api.routes.graph.graph_api.get_node", mock_get_node)

        response = await async_client.post(
            "/api/v1/graph/query",
            json={
                "action": "analysis_edges_by_task",
                "task_id": "task-123",
                "only_path": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_analysis_edges_by_task_missing_task_id(self, async_client):
        """测试 analysis_edges_by_task action 缺少 task_id"""
        response = await async_client.post(
            "/api/v1/graph/query",
            json={"action": "analysis_edges_by_task"},
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "BAD_REQUEST"
        assert "task_id is required" in data["error"]["message"]

    @pytest.mark.asyncio
    async def test_shortest_path_in_window_action_success(self, async_client, monkeypatch: pytest.MonkeyPatch):
        """测试 shortest_path_in_window action 成功场景"""
        def mock_gds_shortest_path(src_uid, dst_uid, t_min, t_max, *, risk_weights, min_risk=0.0, allowed_reltypes=None):
            return (1.5, [])  # (cost, edges)

        def mock_get_node(uid):
            return None

        monkeypatch.setattr("app.api.routes.graph.graph_api.gds_shortest_path_in_window", mock_gds_shortest_path)
        monkeypatch.setattr("app.api.routes.graph.graph_api.get_node", mock_get_node)

        response = await async_client.post(
            "/api/v1/graph/query",
            json={
                "action": "shortest_path_in_window",
                "src_uid": "Process:process.entity_id=p-001",
                "dst_uid": "IP:ip=93.184.216.1",
                "start_ts": "2024-01-01T00:00:00Z",
                "end_ts": "2024-01-02T00:00:00Z",
                "risk_weights": {"NET_CONNECT": 1.0},
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["found"] is True
        assert data["cost"] == 1.5

    @pytest.mark.asyncio
    async def test_shortest_path_missing_src_dst(self, async_client):
        """测试 shortest_path_in_window action 缺少 src_uid/dst_uid"""
        response = await async_client.post(
            "/api/v1/graph/query",
            json={
                "action": "shortest_path_in_window",
                "start_ts": "2024-01-01T00:00:00Z",
                "end_ts": "2024-01-02T00:00:00Z",
            },
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "BAD_REQUEST"
        assert "src_uid and dst_uid are required" in data["error"]["message"]

    @pytest.mark.asyncio
    async def test_shortest_path_missing_risk_weights(self, async_client):
        """测试 shortest_path_in_window action 缺少 risk_weights"""
        response = await async_client.post(
            "/api/v1/graph/query",
            json={
                "action": "shortest_path_in_window",
                "src_uid": "Process:process.entity_id=p-001",
                "dst_uid": "IP:ip=93.184.216.1",
                "start_ts": "2024-01-01T00:00:00Z",
                "end_ts": "2024-01-02T00:00:00Z",
            },
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "BAD_REQUEST"
        assert "risk_weights is required" in data["error"]["message"]

    @pytest.mark.asyncio
    async def test_unknown_action(self, async_client):
        """测试未知的 action (Pydantic 验证失败返回 422)"""
        response = await async_client.post(
            "/api/v1/graph/query",
            json={"action": "unknown_action"},
        )
        assert response.status_code == 422
        data = response.json()
        # Pydantic validation error format
        assert "detail" in data
