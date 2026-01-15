"""测试批量入图集成"""
from __future__ import annotations

import pytest

from app.services.neo4j import ingest as graph_ingest
from app.services.neo4j import db as graph_db


@pytest.mark.requires_neo4j
def test_batch_ingest_multiple_events():
    """测试批量入图多个事件"""
    events = [
        {
            "@timestamp": "2026-01-15T10:00:00Z",
            "event": {
                "id": "evt-001",
                "kind": "event",
                "category": ["authentication"],
                "dataset": "hostlog.auth",
                "action": "logged_in",
            },
            "host": {"id": "h-001", "name": "victim-01"},
            "user": {"id": "u-001", "name": "alice"},
        },
        {
            "@timestamp": "2026-01-15T10:01:00Z",
            "event": {
                "id": "evt-002",
                "kind": "event",
                "category": ["process"],
                "dataset": "hostlog.process",
                "action": "fork",
            },
            "host": {"id": "h-001"},
            "process": {
                "entity_id": "p-001",
                "pid": 123,
                "executable": "/bin/bash",
                "parent": {
                    "entity_id": "p-002",
                    "pid": 1,
                    "executable": "/sbin/init",
                },
            },
        },
    ]

    total_nodes, total_edges = graph_ingest.ingest_ecs_events(events)

    assert total_nodes > 0
    assert total_edges > 0


@pytest.mark.requires_neo4j
def test_batch_ingest_idempotent():
    """测试批量入图幂等性（重复入图相同事件）"""
    events = [
        {
            "@timestamp": "2026-01-15T10:00:00Z",
            "event": {
                "id": "evt-001",
                "kind": "event",
                "category": ["authentication"],
            },
            "host": {"id": "h-001", "name": "victim-01"},
            "user": {"id": "u-001", "name": "alice"},
        },
    ]

    # 第一次入图
    nodes1, edges1 = graph_ingest.ingest_ecs_events(events)

    # 第二次入图（幂等）
    nodes2, edges2 = graph_ingest.ingest_ecs_events(events)

    # 节点和边数量应该相同（没有重复）
    assert nodes1 == nodes2
    assert edges1 == edges2


@pytest.mark.requires_neo4j
def test_batch_ingest_canonical_finding():
    """测试批量入图 Canonical Finding"""
    events = [
        {
            "@timestamp": "2026-01-15T10:00:00Z",
            "event": {
                "id": "evt-alert-001",
                "kind": "alert",
                "dataset": "finding.canonical",
                "severity": 50,
                "category": ["authentication"],
            },
            "host": {"id": "h-001", "name": "victim-01"},
            "user": {"id": "u-001", "name": "attacker"},
            "threat": {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0001",
                    "name": "Initial Access",
                },
                "technique": {
                    "id": "T1078",
                    "name": "Valid Accounts",
                },
            },
            "custom": {
                "evidence": {
                    "event_ids": ["evt-001", "evt-002"]
                },
                "finding": {
                    "stage": "detection",
                }
            }
        },
    ]

    total_nodes, total_edges = graph_ingest.ingest_ecs_events(events)

    assert total_nodes > 0
    assert total_edges > 0

    # 验证告警边包含 is_alarm=true
    with graph_db._get_session() as session:
        records = list(
            session.run(
                "MATCH ()-[r]->() "
                "WHERE r.`event.id` = $event_id "
                "RETURN r.is_alarm AS is_alarm",
                event_id="evt-alert-001"
            )
        )
    assert len(records) > 0
    assert records[0]["is_alarm"] == True


@pytest.mark.requires_neo4j
def test_batch_ingest_preserves_evidence_ids():
    """测试批量入图保留证据 ID"""
    events = [
        {
            "@timestamp": "2026-01-15T10:00:00Z",
            "event": {
                "id": "evt-alert-001",
                "kind": "alert",
                "dataset": "finding.canonical",
                "category": ["authentication"],
            },
            "host": {"id": "h-001", "name": "victim-01"},
            "user": {"id": "u-001", "name": "attacker"},
            "custom": {
                "evidence": {
                    "event_ids": ["evt-001", "evt-002", "evt-003"]
                }
            }
        },
    ]

    total_nodes, total_edges = graph_ingest.ingest_ecs_events(events)

    assert total_edges > 0

    # 验证边包含 custom.evidence.event_ids
    with graph_db._get_session() as session:
        records = list(
            session.run(
                "MATCH ()-[r]->() "
                "WHERE r.`event.id` = $event_id "
                "RETURN r.`custom.evidence.event_ids` AS evidence_ids",
                event_id="evt-alert-001"
            )
        )
    assert len(records) > 0
    evidence_ids = records[0]["evidence_ids"]
    assert isinstance(evidence_ids, list)
    assert len(evidence_ids) == 3
    assert "evt-001" in evidence_ids
    assert "evt-002" in evidence_ids
    assert "evt-003" in evidence_ids


@pytest.mark.requires_neo4j
def test_batch_ingest_with_file_access():
    """测试批量入图文件访问事件"""
    events = [
        {
            "@timestamp": "2026-01-15T10:00:00Z",
            "event": {
                "id": "evt-001",
                "kind": "event",
                "dataset": "hostbehavior.file",
                "action": "write",
            },
            "host": {"id": "h-001"},
            "process": {
                "entity_id": "p-001",
                "pid": 1234,
                "executable": "/bin/vi",
            },
            "file": {
                "path": "/etc/passwd",
            },
        },
    ]

    total_nodes, total_edges = graph_ingest.ingest_ecs_events(events)

    assert total_nodes > 0
    assert total_edges > 0

    # 验证创建了 File 节点和 FILE_ACCESS 边
    with graph_db._get_session() as session:
        records = list(
            session.run(
                "MATCH (n:File) WHERE n.`file.path` = '/etc/passwd' RETURN n LIMIT 1"
            )
        )
    assert len(records) > 0

    with graph_db._get_session() as session:
        records = list(
            session.run(
                "MATCH ()-[r:FILE_ACCESS]->() "
                "WHERE r.`event.id` = 'evt-001' "
                "RETURN r.op AS op"
            )
        )
    assert len(records) > 0
    assert records[0]["op"] == "write"


@pytest.mark.requires_neo4j
def test_batch_ingest_cleanup():
    """清理测试数据"""
    # 删除所有测试边
    with graph_db._get_session() as session:
        session.run("MATCH ()-[r]->() WHERE r.`event.id` STARTS WITH 'evt-' DELETE r")

    # 删除测试节点
    with graph_db._get_session() as session:
        session.run("MATCH (n) WHERE n.`host.id` = 'h-001' DETACH DELETE n")
        session.run("MATCH (n) WHERE n.`user.id` = 'u-001' DETACH DELETE n")
        session.run("MATCH (n) WHERE n.`process.entity_id` = 'p-001' DETACH DELETE n")
