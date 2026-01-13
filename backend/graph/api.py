from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Iterable, Mapping

from neo4j import GraphDatabase

from graph.ecs_ingest import ecs_event_to_graph
from graph.models import (
    GraphEdge,
    GraphNode,
    NodeType,
    RelType,
    NODE_UNIQUE_KEY,
    build_uid,
    parse_uid,
)

_DRIVER = None
_SCHEMA_READY = False


def _get_driver():
    # 获取并缓存 Neo4j 驱动
    global _DRIVER
    if _DRIVER is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "password")
        _DRIVER = GraphDatabase.driver(uri, auth=(user, password))
    return _DRIVER


def _get_session():
    # 创建数据库会话（支持指定数据库名）
    driver = _get_driver()
    database = os.getenv("NEO4J_DATABASE")
    if database:
        return driver.session(database=database)
    return driver.session()


def _execute_write(session, func, *args, **kwargs):
    # 兼容不同版本驱动的写事务调用
    if hasattr(session, "execute_write"):
        return session.execute_write(func, *args, **kwargs)
    return session.write_transaction(func, *args, **kwargs)


def _execute_read(session, func, *args, **kwargs):
    # 兼容不同版本驱动的读事务调用
    if hasattr(session, "execute_read"):
        return session.execute_read(func, *args, **kwargs)
    return session.read_transaction(func, *args, **kwargs)


def _param_key(name: str) -> str:
    # 将属性名转为可用于 Cypher 参数的安全键
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)
    return f"key_{safe}"


def _cypher_prop(name: str) -> str:
    # 处理包含特殊字符的属性名（如点号）
    escaped = name.replace("`", "``")
    return f"`{escaped}`"


def _name_suffix(name: str) -> str:
    # 将属性名转换为索引/约束名后缀
    return "".join(ch if ch.isalnum() else "_" for ch in name)


def ensure_schema() -> None:
    # 确保图数据库约束和索引已创建
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _get_session() as session:
        _execute_write(session, _create_schema)
    _SCHEMA_READY = True


def _create_schema(tx) -> None:
    # 创建节点唯一约束与常用索引
    constraints = [
        ("Host", "host.id"),
        ("User", "user.name"),
        ("Process", "process.entity_id"),
        ("File", "file.path"),
        ("Domain", "dns.question.name"),
        ("IP", "related.ip"),
        ("NetConn", "flow.id"),
    ]
    indexes = [
        ("Host", "host.name"),
        ("User", "user.id"),
        ("Process", "process.executable"),
        ("File", "file.hash.sha256"),
        ("Domain", "url.domain"),
        ("NetConn", "network.community_id"),
    ]
    for label, prop in constraints:
        cname = f"{label.lower()}_{_name_suffix(prop)}_unique"
        tx.run(
            f"CREATE CONSTRAINT {cname} IF NOT EXISTS FOR (n:{label}) "
            f"REQUIRE n.{_cypher_prop(prop)} IS UNIQUE"
        )
    for label, prop in indexes:
        iname = f"{label.lower()}_{_name_suffix(prop)}_index"
        tx.run(f"CREATE INDEX {iname} IF NOT EXISTS FOR (n:{label}) ON (n.{_cypher_prop(prop)})")


def add_node(node: GraphNode) -> None:
    # 写入/合并节点
    ensure_schema()
    with _get_session() as session:
        _execute_write(session, _merge_node, node)


def _merge_node(tx, node: GraphNode) -> None:
    # 以唯一键合并节点并更新属性
    label = node.ntype.value
    key_props = node.key
    merged_props = node.merged_props()
    params: dict[str, Any] = {"props": merged_props}
    key_clause_parts = []
    for k, v in key_props.items():
        param = _param_key(k)
        key_clause_parts.append(f"{_cypher_prop(k)}: ${param}")
        params[param] = v
    key_clause = ", ".join(key_clause_parts)
    tx.run(f"MERGE (n:{label} {{{key_clause}}}) SET n += $props", **params)


def add_edge(edge: GraphEdge) -> None:
    # 写入关系边
    ensure_schema()
    with _get_session() as session:
        _execute_write(session, _create_edge, edge)


def _create_edge(tx, edge: GraphEdge) -> None:
    # 合并起止节点并创建关系
    src_label, src_key = parse_uid(edge.src_uid)
    dst_label, dst_key = parse_uid(edge.dst_uid)
    params: dict[str, Any] = {"props": edge.props}

    src_clause_parts = []
    for k, v in src_key.items():
        param = _param_key(f"src_{k}")
        src_clause_parts.append(f"{_cypher_prop(k)}: ${param}")
        params[param] = v
    src_clause = ", ".join(src_clause_parts)

    dst_clause_parts = []
    for k, v in dst_key.items():
        param = _param_key(f"dst_{k}")
        dst_clause_parts.append(f"{_cypher_prop(k)}: ${param}")
        params[param] = v
    dst_clause = ", ".join(dst_clause_parts)

    cypher = (
        f"MERGE (s:{src_label.value} {{{src_clause}}}) "
        f"MERGE (d:{dst_label.value} {{{dst_clause}}}) "
        f"CREATE (s)-[r:{edge.rtype.value}]->(d) "
        "SET r += $props"
    )
    tx.run(cypher, **params)


def get_node(uid: str) -> GraphNode | None:
    # 按 UID 查询节点
    label, key = parse_uid(uid)
    with _get_session() as session:
        props = _execute_read(session, _fetch_node, label, key)
    if props is None:
        return None
    node_props = dict(props)
    for k in key:
        node_props.pop(k, None)
    return GraphNode(ntype=label, key=key, props=node_props)


def _fetch_node(tx, label: NodeType, key: dict[str, Any]) -> dict[str, Any] | None:
    # 事务内按唯一键读取节点属性
    params: dict[str, Any] = {}
    clause_parts = []
    for k, v in key.items():
        param = _param_key(k)
        clause_parts.append(f"{_cypher_prop(k)}: ${param}")
        params[param] = v
    clause = ", ".join(clause_parts)
    cypher = f"MATCH (n:{label.value} {{{clause}}}) RETURN properties(n) AS props LIMIT 1"
    record = tx.run(cypher, **params).single()
    if record is None:
        return None
    return record["props"]


def get_edges(node: GraphNode) -> list[GraphEdge]:
    # 获取节点的所有相邻关系
    with _get_session() as session:
        rows = _execute_read(session, _fetch_edges, node)
    edges: list[GraphEdge] = []
    for row in rows:
        src_uid = _node_uid_from_record(row["src_labels"], row["src_props"])
        dst_uid = _node_uid_from_record(row["dst_labels"], row["dst_props"])
        if src_uid is None or dst_uid is None:
            continue
        try:
            rtype = RelType(row["rtype"])
        except ValueError:
            continue
        edges.append(GraphEdge(src_uid=src_uid, dst_uid=dst_uid, rtype=rtype, props=row["rprops"]))
    return edges


def _fetch_edges(tx, node: GraphNode) -> list[dict[str, Any]]:
    # 事务内查询节点的关系及其两端节点属性
    params: dict[str, Any] = {}
    clause_parts = []
    for k, v in node.key.items():
        param = _param_key(k)
        clause_parts.append(f"{_cypher_prop(k)}: ${param}")
        params[param] = v
    clause = ", ".join(clause_parts)
    cypher = (
        f"MATCH (n:{node.ntype.value} {{{clause}}})-[r]-(m) "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    return list(tx.run(cypher, **params))


def get_alarm_edges() -> list[GraphEdge]:
    # 获取标记为告警的关系边
    with _get_session() as session:
        rows = _execute_read(session, _fetch_alarm_edges)
    edges: list[GraphEdge] = []
    for row in rows:
        src_uid = _node_uid_from_record(row["src_labels"], row["src_props"])
        dst_uid = _node_uid_from_record(row["dst_labels"], row["dst_props"])
        if src_uid is None or dst_uid is None:
            continue
        try:
            rtype = RelType(row["rtype"])
        except ValueError:
            continue
        edges.append(GraphEdge(src_uid=src_uid, dst_uid=dst_uid, rtype=rtype, props=row["rprops"]))
    return edges


def _fetch_alarm_edges(tx) -> list[dict[str, Any]]:
    # 事务内查询告警边
    cypher = (
        "MATCH ()-[r]->() "
        "WHERE coalesce(r.is_alarm, false) = true "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    return list(tx.run(cypher))


def _node_uid_from_record(labels: Iterable[str], props: dict[str, Any]) -> str | None:
    # 根据记录中的标签与属性推断节点 UID
    ntype = _label_to_ntype(labels)
    if ntype is None:
        return None
    key_field = NODE_UNIQUE_KEY.get(ntype)
    if key_field and key_field in props:
        return build_uid(ntype, {key_field: props[key_field]})
    fallback = _fallback_key(ntype, props)
    if fallback:
        return build_uid(ntype, fallback)
    return None


def _label_to_ntype(labels: Iterable[str]) -> NodeType | None:
    # 将 Neo4j label 映射为节点类型枚举
    for label in labels:
        try:
            return NodeType(label)
        except ValueError:
            continue
    return None


def _fallback_key(ntype: NodeType, props: dict[str, Any]) -> dict[str, Any] | None:
    # 当唯一键缺失时的回退键选择
    fallback_fields = {
        NodeType.HOST: ["host.id", "host.name"],
        NodeType.USER: ["user.name", "user.id"],
        NodeType.PROCESS: ["process.entity_id"],
        NodeType.FILE: ["file.path", "file.hash.sha256", "file.hash.sha1", "file.hash.md5"],
        NodeType.DOMAIN: ["dns.question.name", "url.domain"],
        NodeType.IP: ["related.ip"],
        NodeType.NETCON: ["flow.id", "network.community_id"],
    }
    for field in fallback_fields.get(ntype, []):
        if field in props:
            return {field: props[field]}
    return None


def close() -> None:
    # 关闭 Neo4j 驱动
    global _DRIVER
    if _DRIVER is None:
        return
    _DRIVER.close()
    _DRIVER = None


def ingest_ecs_event(event: Mapping[str, Any]) -> tuple[int, int]:
    # 将单条 ECS 事件写入图数据库
    nodes, edges = ecs_event_to_graph(event)
    for node in nodes:
        add_node(node)
    for edge in edges:
        add_edge(edge)
    return len(nodes), len(edges)


def ingest_ecs_events(events: Iterable[Mapping[str, Any]]) -> tuple[int, int]:
    # 批量写入 ECS 事件
    total_nodes = 0
    total_edges = 0
    for event in events:
        nodes, edges = ecs_event_to_graph(event)
        for node in nodes:
            add_node(node)
        for edge in edges:
            add_edge(edge)
        total_nodes += len(nodes)
        total_edges += len(edges)
    return total_nodes, total_edges


def ingest_from_opensearch(
    query: Mapping[str, Any] | None = None,
    *,
    size: int = 100,
    include_events: bool = True,
    include_raw_findings: bool = True,
    include_canonical_findings: bool = True,
    date: datetime | None = None,
) -> tuple[int, int, int]:
    # 使用 OpenSearch API 拉取 ECS 事件并写入 Neo4j
    from opensearch import INDEX_PATTERNS, get_index_name, index_exists, search

    query_body = dict(query) if query is not None else {"match_all": {}}
    index_names: list[str] = []
    if include_events:
        index_names.append(get_index_name(INDEX_PATTERNS["ECS_EVENTS"], date))
    if include_raw_findings:
        index_names.append(get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], date))
    if include_canonical_findings:
        index_names.append(get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], date))

    total_events = 0
    total_nodes = 0
    total_edges = 0

    for index_name in index_names:
        if not index_exists(index_name):
            continue
        events = search(index_name, query_body, size=size)
        if not events:
            continue
        total_events += len(events)
        node_count, edge_count = ingest_ecs_events(events)
        total_nodes += node_count
        total_edges += edge_count

    return total_events, total_nodes, total_edges
