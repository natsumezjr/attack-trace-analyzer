"""测试 Neo4j 批量写入功能"""
from __future__ import annotations

import pytest

from app.services.neo4j import db, models


class TestNodeGrouping:
    """测试节点分组逻辑"""

    def test_group_nodes_by_type_empty(self):
        """测试空列表分组"""
        assert db._group_nodes_by_type([]) == {}

    def test_group_nodes_by_type_single_type(self):
        """测试单一类型分组"""
        nodes = [
            models.host_node(host_id="h-001"),
            models.host_node(host_id="h-002"),
        ]
        grouped = db._group_nodes_by_type(nodes)
        assert len(grouped) == 1
        assert len(grouped[models.NodeType.HOST]) == 2

    def test_group_nodes_by_type_multiple_types(self):
        """测试多类型分组"""
        nodes = [
            models.host_node(host_id="h-001"),
            models.user_node(user_id="u-001"),
            models.host_node(host_id="h-002"),
        ]
        grouped = db._group_nodes_by_type(nodes)
        assert len(grouped[models.NodeType.HOST]) == 2
        assert len(grouped[models.NodeType.USER]) == 1


class TestUnwindParams:
    """测试 UNWIND 参数构建"""

    def test_build_unwind_params_single_key(self):
        """测试单键节点参数构建"""
        nodes = [models.host_node(host_id="h-001", host_name="victim-01")]
        params = db._build_unwind_params(nodes, ["host.id"])

        assert len(params) == 1
        assert params[0]["key_val"] == "h-001"
        assert params[0]["props"]["host.id"] == "h-001"
        assert params[0]["props"]["host.name"] == "victim-01"

    def test_build_unwind_params_composite_key(self):
        """测试复合键节点参数构建"""
        nodes = [
            models.file_node(host_id="h-001", path="/tmp/file.txt")
        ]
        params = db._build_unwind_params(nodes, ["host.id", "file.path"])

        assert len(params) == 1
        assert params[0]["key_0"] == "h-001"
        assert params[0]["key_1"] == "/tmp/file.txt"
        assert params[0]["props"]["host.id"] == "h-001"
        assert params[0]["props"]["file.path"] == "/tmp/file.txt"


class TestBatchMergeCypher:
    """测试批量 MERGE Cypher 生成"""

    def test_build_batch_merge_cypher_single_key(self):
        """测试单键 Cypher 生成"""
        cypher = db._build_batch_merge_cypher(
            models.NodeType.HOST,
            ["host.id"]
        )
        assert "UNWIND $nodes AS node" in cypher
        assert "MERGE (n:Host" in cypher
        assert "node.key_val" in cypher
        assert "SET n += node.props" in cypher

    def test_build_batch_merge_cypher_composite_key(self):
        """测试复合键 Cypher 生成"""
        cypher = db._build_batch_merge_cypher(
            models.NodeType.FILE,
            ["host.id", "file.path"]
        )
        assert "UNWIND $nodes AS node" in cypher
        assert "MERGE (n:File" in cypher
        assert "node.key_0" in cypher
        assert "node.key_1" in cypher
        assert "SET n += node.props" in cypher


class TestBatchWriteIdempotency:
    """测试批量写入幂等性"""

    @pytest.mark.requires_neo4j
    def test_batch_merge_nodes_is_idempotent(self):
        """测试节点批量写入幂等性"""
        nodes = [models.host_node(host_id="h-001")]

        # 第一次写入
        count1, _ = db.add_nodes_and_edges(nodes, [])
        assert count1 == 1

        # 第二次写入（幂等）
        count2, _ = db.add_nodes_and_edges(nodes, [])
        assert count2 == 1  # 仍然是 1，没有重复

    @pytest.mark.requires_neo4j
    def test_batch_merge_edges_is_idempotent(self):
        """测试边批量写入幂等性"""
        nodes = [
            models.user_node(user_id="u-001"),
            models.host_node(host_id="h-001"),
        ]
        edges = [
            models.make_edge(
                src=nodes[0],
                dst=nodes[1],
                rtype=models.RelType.LOGON,
                props={"event.id": "evt-001"}
            )
        ]

        # 第一次写入
        _, count1 = db.add_nodes_and_edges(nodes, edges)
        assert count1 == 1

        # 第二次写入（幂等）
        _, count2 = db.add_nodes_and_edges(nodes, edges)
        assert count2 == 1


class TestBatchWriteFunctional:
    """测试批量写入功能性"""

    @pytest.mark.requires_neo4j
    def test_batch_write_mixed_node_types(self):
        """测试批量写入混合节点类型"""
        nodes = [
            models.host_node(host_id="h-001"),
            models.user_node(user_id="u-001"),
            models.process_node(
                process_entity_id="p-001",
                pid=123,
                executable="/bin/bash",
                host_id="h-001"
            ),
        ]
        edges = []

        count, _ = db.add_nodes_and_edges(nodes, edges)
        assert count == 3

    @pytest.mark.requires_neo4j
    def test_batch_write_with_edges(self):
        """测试批量写入节点和边"""
        nodes = [
            models.user_node(user_id="u-001"),
            models.host_node(host_id="h-001"),
        ]
        edges = [
            models.make_edge(
                src=nodes[0],
                dst=nodes[1],
                rtype=models.RelType.LOGON,
                props={
                    "event.id": "evt-001",
                    "ts": "2026-01-15T10:00:00Z",
                    "ts_float": 1736942400.0,
                }
            )
        ]

        node_count, edge_count = db.add_nodes_and_edges(nodes, edges)
        assert node_count == 2
        assert edge_count == 1

    @pytest.mark.requires_neo4j
    def test_batch_write_empty_inputs(self):
        """测试批量写入空输入"""
        node_count, edge_count = db.add_nodes_and_edges([], [])
        assert node_count == 0
        assert edge_count == 0
