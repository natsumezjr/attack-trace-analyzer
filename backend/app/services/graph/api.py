from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Iterable, Mapping
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

# Optional: ECS ingest integration (legacy compatibility)
try:
    from .ecs_ingest import ecs_event_to_graph  # type: ignore
except Exception:
    ecs_event_to_graph = None  # type: ignore

from .models import (
    GraphEdge,
    GraphNode,
    NodeType,
    RelType,
    NODE_UNIQUE_KEY,
    build_uid,
    parse_uid,
)
from .utils import _parse_ts_to_float


# 全局驱动与 Schema 初始化状态
_DRIVER = None
_SCHEMA_READY = False


# 获取/缓存 Neo4j driver
def _get_driver():
    global _DRIVER
    if _DRIVER is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "password")
        _DRIVER = GraphDatabase.driver(uri, auth=(user, password))
    return _DRIVER


# 获取 session（支持指定数据库）
def _get_session():
    driver = _get_driver()
    database = os.getenv("NEO4J_DATABASE")
    if database:
        return driver.session(database=database)
    return driver.session()


def _execute_write(session, func, *args, **kwargs):
    if hasattr(session, "execute_write"):
        return session.execute_write(func, *args, **kwargs)
    return session.write_transaction(func, *args, **kwargs)


def _execute_read(session, func, *args, **kwargs):
    if hasattr(session, "execute_read"):
        return session.execute_read(func, *args, **kwargs)
    return session.read_transaction(func, *args, **kwargs)


def _param_key(name: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)
    return f"key_{safe}"


def _cypher_prop(name: str) -> str:
    escaped = name.replace("`", "``")
    return f"`{escaped}`"


def _name_suffix(name: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in name)


# 初始化约束与索引（只执行一次）
def ensure_schema() -> None:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _get_session() as session:
        _execute_write(session, _create_schema)
    _SCHEMA_READY = True


def _create_schema(tx) -> None:
    # v2 schema aligns with docs/52 (no NetConn nodes; composite keys for User/File).
    constraints: list[tuple[str, tuple[str, ...]]] = [
        ("Host", ("host.id",)),
        ("User", ("user.id",)),
        ("User", ("host.id", "user.name")),
        ("Process", ("process.entity_id",)),
        ("File", ("host.id", "file.path")),
        ("Domain", ("domain.name",)),
        ("IP", ("ip",)),
    ]
    indexes: list[tuple[str, str]] = [
        ("Host", "host.name"),
        ("User", "user.name"),
        ("Process", "process.executable"),
        ("File", "file.path"),
        ("Domain", "domain.name"),
        ("IP", "ip"),
    ]

    for label, props in constraints:
        suffix = "_".join(_name_suffix(p) for p in props)
        cname = f"{label.lower()}_{suffix}_unique"
        if len(props) == 1:
            prop = props[0]
            tx.run(
                f"CREATE CONSTRAINT {cname} IF NOT EXISTS FOR (n:{label}) "
                f"REQUIRE n.{_cypher_prop(prop)} IS UNIQUE"
            )
        else:
            prop_list = ", ".join(f"n.{_cypher_prop(p)}" for p in props)
            tx.run(
                f"CREATE CONSTRAINT {cname} IF NOT EXISTS FOR (n:{label}) "
                f"REQUIRE ({prop_list}) IS UNIQUE"
            )

    for label, prop in indexes:
        iname = f"{label.lower()}_{_name_suffix(prop)}_index"
        tx.run(f"CREATE INDEX {iname} IF NOT EXISTS FOR (n:{label}) ON (n.{_cypher_prop(prop)})")


# 写入节点（基于唯一键 MERGE）
def add_node(node: GraphNode) -> None:
    ensure_schema()
    with _get_session() as session:
        _execute_write(session, _merge_node, node)


def _merge_node(tx, node: GraphNode) -> None:
    label = node.ntype.value
    key_props = node.key
    merged_props = node.merged_props()
    params: Dict[str, Any] = {"props": merged_props}

    key_clause_parts = []
    for k, v in key_props.items():
        param = _param_key(k)
        key_clause_parts.append(f"{_cypher_prop(k)}: ${param}")
        params[param] = v
    key_clause = ", ".join(key_clause_parts)

    tx.run(f"MERGE (n:{label} {{{key_clause}}}) SET n += $props", **params)


# 写入关系边（按证据追加）
def add_edge(edge: GraphEdge) -> None:
    """Create an edge in Neo4j.

    关键：为 Phase B 的窗口过滤和 GDS 投影，写入数值时间戳 r.ts_float。
    """
    ensure_schema()

    # Best-effort: store a numeric timestamp for window/GDS queries.
    try:
        if isinstance(getattr(edge, "props", None), dict):
            ts_float = edge.props.get("ts_float")
            if not isinstance(ts_float, (int, float)):
                ts = edge.get_ts() if hasattr(edge, "get_ts") else None
                if ts is not None:
                    edge.props["ts_float"] = _parse_ts_to_float(str(ts))
    except Exception:
        pass

    with _get_session() as session:
        _execute_write(session, _create_edge, edge)


def _create_edge(tx, edge: GraphEdge) -> None:
    src_label, src_key = parse_uid(edge.src_uid)
    dst_label, dst_key = parse_uid(edge.dst_uid)

    params: Dict[str, Any] = {"props": edge.props}

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


# 按 UID 查询单个节点
def get_node(uid: str) -> Optional[GraphNode]:
    label, key = parse_uid(uid)
    with _get_session() as session:
        props = _execute_read(session, _fetch_node, label, key)
    if props is None:
        return None
    node_props = dict(props)
    for k in key:
        node_props.pop(k, None)
    return GraphNode(ntype=label, key=key, props=node_props)


def _fetch_node(tx, label: NodeType, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    params: Dict[str, Any] = {}
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


# 查询节点相关边
def get_edges(node: GraphNode) -> List[GraphEdge]:
    with _get_session() as session:
        rows = _execute_read(session, _fetch_edges, node)
    edges: List[GraphEdge] = []
    for row in rows:
        src_uid = _node_uid_from_record(row["src_labels"], row["src_props"])
        dst_uid = _node_uid_from_record(row["dst_labels"], row["dst_props"])
        if src_uid is None or dst_uid is None:
            continue
        try:
            rtype = RelType(row["rtype"])
        except ValueError:
            continue
        edges.append(GraphEdge(src_uid=src_uid, dst_uid=dst_uid, rtype=rtype, props=dict(row["rprops"])))
    return edges


def _fetch_edges(tx, node: GraphNode) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {}
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


# 查询告警边集合
def get_alarm_edges() -> List[GraphEdge]:
    """Return all edges labeled as alarms (r.is_alarm = true)."""
    with _get_session() as session:
        rows = _execute_read(session, _fetch_alarm_edges)
    edges: List[GraphEdge] = []
    for row in rows:
        src_uid = _node_uid_from_record(row["src_labels"], row["src_props"])
        dst_uid = _node_uid_from_record(row["dst_labels"], row["dst_props"])
        if src_uid is None or dst_uid is None:
            continue
        try:
            rtype = RelType(row["rtype"])
        except ValueError:
            continue
        edges.append(GraphEdge(src_uid=src_uid, dst_uid=dst_uid, rtype=rtype, props=dict(row["rprops"])))
    return edges


def _fetch_alarm_edges(tx) -> List[Dict[str, Any]]:
    cypher = (
        "MATCH ()-[r]->() "
        "WHERE coalesce(r.is_alarm, false) = true "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    return list(tx.run(cypher))


# 按时间窗查询边集合（可选关系类型/告警过滤）
def get_edges_in_window(
    *,
    t_min: float,
    t_max: float,
) -> List[GraphEdge]:
    """Fetch edges with numeric timestamp within [t_min, t_max]."""
    pass


def _fetch_edges_in_window(
    tx,
    t_min: float,
    t_max: float,
    allowed_reltypes: Optional[Sequence[str]],
    only_alarm: bool,
) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {
        "t_min": float(t_min),
        "t_max": float(t_max),
        "allowed": list(allowed_reltypes) if allowed_reltypes else None,
        "only_alarm": bool(only_alarm),
    }

    cypher = (
        "MATCH ()-[r]->() "
        "WHERE coalesce(r.ts_float, 0.0) >= $t_min AND coalesce(r.ts_float, 0.0) <= $t_max "
        "AND ($allowed IS NULL OR type(r) IN $allowed) "
        "AND (NOT $only_alarm OR coalesce(r.is_alarm, false) = true) "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    return list(tx.run(cypher, **params))





# 基于 GDS 的时间窗最短路
def gds_shortest_path_in_window(
    src_uid: str,
    dst_uid: str,
    t_min: float,
    t_max: float,
    *,
    risk_weights: Mapping[str, float],
    min_risk: float = 0.0,
    allowed_reltypes: Optional[Sequence[str]] = None,
) -> Optional[Tuple[float, List[GraphEdge]]]:
    """Compute weighted shortest path via Neo4j GDS on a time-window projected graph."""
    if src_uid == dst_uid:
        return 0.0, []

    ensure_schema()
    graph_name = f"kc_window_{uuid.uuid4().hex}"

    with _get_session() as session:
        return _execute_read(
            session,
            _gds_shortest_path_in_window_tx,
            graph_name,
            src_uid,
            dst_uid,
            float(t_min),
            float(t_max),
            dict(risk_weights),
            float(min_risk),
            list(allowed_reltypes) if allowed_reltypes else None,
        )


def _match_clause_for_uid(uid: str, alias: str, params: Dict[str, Any], prefix: str) -> str:
    label, key = parse_uid(uid)
    clause_parts = []
    for k, v in key.items():
        p = _param_key(f"{prefix}_{k}")
        params[p] = v
        clause_parts.append(f"{_cypher_prop(k)}: ${p}")
    clause = ", ".join(clause_parts)
    return f"MATCH ({alias}:{label.value} {{{clause}}})"


def _gds_shortest_path_in_window_tx(
    tx,
    graph_name: str,
    src_uid: str,
    dst_uid: str,
    t_min: float,
    t_max: float,
    risk_weights: Dict[str, float],
    min_risk: float,
    allowed_reltypes: Optional[List[str]],
) -> Optional[Tuple[float, List[GraphEdge]]]:
    params: Dict[str, Any] = {
        "graph_name": graph_name,
        "t_min": t_min,
        "t_max": t_max,
        "risk_map": risk_weights,
        "default_risk": 1.0,
        "min_risk": min_risk,
        "allowed": allowed_reltypes,
        "max_risk": max(risk_weights.values()) if risk_weights else 1.0,
    }

    match_source = _match_clause_for_uid(src_uid, "source", params, "src")
    match_target = _match_clause_for_uid(dst_uid, "target", params, "dst")

    rel_match = (
        "MATCH (s)-[r]->(t) "
        "WHERE coalesce(r.ts_float, 0.0) >= $t_min AND coalesce(r.ts_float, 0.0) <= $t_max "
        "AND ($allowed IS NULL OR type(r) IN $allowed) "
        "WITH s, r, t, coalesce($risk_map[type(r)], $default_risk) AS risk "
        "WHERE risk >= $min_risk "
    )

    node_query = (
        f"{rel_match} RETURN DISTINCT id(s) AS id "
        "UNION "
        f"{rel_match} RETURN DISTINCT id(t) AS id "
        "UNION "
        f"{match_source} RETURN id(source) AS id "
        "UNION "
        f"{match_target} RETURN id(target) AS id"
    )

    rel_query = (
        f"{rel_match} "
        "RETURN id(s) AS source, id(t) AS target, type(r) AS type, "
        "($max_risk + 1.0 - risk) AS cost"
    )

    project_cypher = (
        "CALL gds.graph.project.cypher($graph_name, $node_query, $rel_query, "
        "{relationshipProperties: ['cost']}) "
        "YIELD graphName"
    )

    try:
        params_proj = dict(params)
        params_proj["node_query"] = node_query
        params_proj["rel_query"] = rel_query
        tx.run(project_cypher, **params_proj).consume()

        dijkstra_with_path = (
            f"{match_source} "
            f"{match_target} "
            "CALL gds.shortestPath.dijkstra.stream($graph_name, {"
            "sourceNode: id(source), targetNode: id(target), relationshipWeightProperty: 'cost'}) "
            "YIELD totalCost, path "
            "WITH totalCost, relationships(path) AS rels "
            "UNWIND rels AS r "
            "RETURN totalCost AS totalCost, "
            "type(r) AS rtype, properties(r) AS rprops, "
            "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
            "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
        )

        rows: List[Dict[str, Any]] = []
        total_cost: Optional[float] = None
        try:
            for rec in tx.run(dijkstra_with_path, **params):
                if total_cost is None:
                    total_cost = float(rec["totalCost"])
                rows.append(rec)
        except Neo4jError:
            dijkstra_nodeids = (
                f"{match_source} "
                f"{match_target} "
                "CALL gds.shortestPath.dijkstra.stream($graph_name, {"
                "sourceNode: id(source), targetNode: id(target), relationshipWeightProperty: 'cost'}) "
                "YIELD totalCost, nodeIds "
                "RETURN totalCost AS totalCost, nodeIds AS nodeIds"
            )
            record = tx.run(dijkstra_nodeids, **params).single()
            if record is None:
                return None
            total_cost = float(record["totalCost"])
            node_ids = record.get("nodeIds") or []
            if len(node_ids) < 2:
                return None

            edge_rows = tx.run(
                _reconstruct_edges_between_node_ids_cypher(node_ids),
                node_ids=node_ids,
                t_min=t_min,
                t_max=t_max,
                allowed=allowed_reltypes,
                risk_map=risk_weights,
                default_risk=1.0,
                min_risk=min_risk,
                max_risk=params["max_risk"],
            )
            rows = list(edge_rows)

        if total_cost is None:
            return None
        if not rows:
            return None

        edges: List[GraphEdge] = []
        for row in rows:
            src_uid2 = _node_uid_from_record(row["src_labels"], row["src_props"])
            dst_uid2 = _node_uid_from_record(row["dst_labels"], row["dst_props"])
            if src_uid2 is None or dst_uid2 is None:
                continue
            try:
                rtype = RelType(row["rtype"])
            except ValueError:
                continue
            edges.append(GraphEdge(src_uid=src_uid2, dst_uid=dst_uid2, rtype=rtype, props=dict(row["rprops"])))

        if not edges:
            return None

        return total_cost, edges

    finally:
        try:
            tx.run("CALL gds.graph.drop($graph_name, false) YIELD graphName", graph_name=graph_name).consume()
        except Exception:
            pass


def _reconstruct_edges_between_node_ids_cypher(node_ids: List[int]) -> str:
    return (
        "UNWIND range(0, size($node_ids)-2) AS i "
        "WITH $node_ids[i] AS sid, $node_ids[i+1] AS tid "
        "MATCH (s)-[r]->(t) "
        "WHERE id(s) = sid AND id(t) = tid "
        "AND coalesce(r.ts_float, 0.0) >= $t_min AND coalesce(r.ts_float, 0.0) <= $t_max "
        "AND ($allowed IS NULL OR type(r) IN $allowed) "
        "WITH s, r, t, coalesce($risk_map[type(r)], $default_risk) AS risk "
        "WHERE risk >= $min_risk "
        "WITH s, r, t, ($max_risk + 1.0 - risk) AS cost "
        "ORDER BY cost ASC "
        "WITH collect({rtype: type(r), rprops: properties(r), "
        "src_labels: labels(s), src_props: properties(s), "
        "dst_labels: labels(t), dst_props: properties(t)})[0] AS best "
        "RETURN best.rtype AS rtype, best.rprops AS rprops, "
        "best.src_labels AS src_labels, best.src_props AS src_props, "
        "best.dst_labels AS dst_labels, best.dst_props AS dst_props"
    )


def _node_uid_from_record(labels: Iterable[str], props: Dict[str, Any]) -> Optional[str]:
    ntype = _label_to_ntype(labels)
    if ntype is None:
        return None
    if ntype == NodeType.USER:
        user_id = props.get("user.id")
        if user_id:
            return build_uid(ntype, {"user.id": user_id})
        host_id = props.get("host.id")
        user_name = props.get("user.name")
        if host_id and user_name:
            return build_uid(ntype, {"host.id": host_id, "user.name": user_name})
    if ntype == NodeType.FILE:
        host_id = props.get("host.id")
        file_path = props.get("file.path")
        if host_id and file_path:
            return build_uid(ntype, {"host.id": host_id, "file.path": file_path})
    key_field = NODE_UNIQUE_KEY.get(ntype)
    if key_field and key_field in props:
        return build_uid(ntype, {key_field: props[key_field]})
    fallback = _fallback_key(ntype, props)
    if fallback:
        return build_uid(ntype, fallback)
    return None


def _label_to_ntype(labels: Iterable[str]) -> Optional[NodeType]:
    for label in labels:
        try:
            return NodeType(label)
        except ValueError:
            continue
    return None


def _fallback_key(ntype: NodeType, props: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    fallback_fields = {
        NodeType.HOST: ["host.id", "host.name"],
        NodeType.USER: ["user.id", "host.id", "user.name"],
        NodeType.PROCESS: ["process.entity_id"],
        NodeType.FILE: ["host.id", "file.path"],
        NodeType.DOMAIN: ["domain.name"],
        NodeType.IP: ["ip"],
    }
    if ntype == NodeType.USER:
        user_id = props.get("user.id")
        if user_id:
            return {"user.id": user_id}
        host_id = props.get("host.id")
        user_name = props.get("user.name")
        if host_id and user_name:
            return {"host.id": host_id, "user.name": user_name}
        return None
    if ntype == NodeType.FILE:
        host_id = props.get("host.id")
        file_path = props.get("file.path")
        if host_id and file_path:
            return {"host.id": host_id, "file.path": file_path}
        return None

    for field in fallback_fields.get(ntype, []):
        if field in props:
            return {field: props[field]}
    return None


def close() -> None:
    global _DRIVER
    if _DRIVER is None:
        return
    _DRIVER.close()
    _DRIVER = None


# 写回溯源结果到边属性（analysis.* 覆盖语义）
def write_analysis_results(
    edges: Sequence[GraphEdge],
    *,
    task_id: str,
    updated_at: str,
) -> int:
    """Write analysis.* fields onto edges and overwrite any existing analysis state."""
    if not edges:
        return 0
    ensure_schema()
    total_updated = 0
    with _get_session() as session:
        for edge in edges:
            total_updated += _execute_write(session, _write_analysis_result_tx, edge, task_id, updated_at)
    return total_updated


def _write_analysis_result_tx(tx, edge: GraphEdge, task_id: str, updated_at: str) -> int:
    if not isinstance(edge.props, dict):
        return 0
    event_id = edge.props.get("event.id")
    if not isinstance(event_id, str) or not event_id:
        return 0

    src_label, src_key = parse_uid(edge.src_uid)
    dst_label, dst_key = parse_uid(edge.dst_uid)

    params: Dict[str, Any] = {"event_id": event_id}

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

    analysis_props: Dict[str, Any] = _analysis_props_from_edge(edge.props, task_id, updated_at)
    params["analysis_props"] = analysis_props

    analysis_fields = [
        "analysis.task_id",
        "analysis.updated_at",
        "analysis.is_path_edge",
        "analysis.risk_score",
        "analysis.ttp.technique_ids",
        "analysis.summary",
    ]
    clear_clause = ", ".join(f"r.{_cypher_prop(field)} = null" for field in analysis_fields)

    cypher = (
        f"MATCH (s:{src_label.value} {{{src_clause}}})-[r:{edge.rtype.value}]->(t:{dst_label.value} {{{dst_clause}}}) "
        "WHERE r.`event.id` = $event_id "
        f"SET {clear_clause} "
        "SET r += $analysis_props "
        "RETURN count(r) AS cnt"
    )
    record = tx.run(cypher, **params).single()
    if record is None:
        return 0
    count = record.get("cnt")
    return int(count) if isinstance(count, (int, float)) else 0


def _analysis_props_from_edge(
    edge_props: Mapping[str, Any],
    task_id: str,
    updated_at: str,
) -> Dict[str, Any]:
    is_path_edge = bool(edge_props.get("analysis.is_path_edge"))
    props: Dict[str, Any] = {
        "analysis.task_id": task_id,
        "analysis.updated_at": updated_at,
        "analysis.is_path_edge": is_path_edge,
    }
    if not is_path_edge:
        return props

    risk_score = edge_props.get("analysis.risk_score")
    if isinstance(risk_score, (int, float)):
        props["analysis.risk_score"] = float(risk_score)

    technique_ids = edge_props.get("analysis.ttp.technique_ids")
    if isinstance(technique_ids, list):
        props["analysis.ttp.technique_ids"] = [v for v in technique_ids if isinstance(v, str) and v]
    elif isinstance(technique_ids, str) and technique_ids:
        props["analysis.ttp.technique_ids"] = [technique_ids]

    summary = edge_props.get("analysis.summary")
    if isinstance(summary, str) and summary:
        props["analysis.summary"] = summary

    return props


# 入图：单条 ECS 文档
def ingest_ecs_event(event: Mapping[str, Any]) -> Tuple[int, int]:
    """Ingest a single ECS event by converting it into nodes/edges."""
    if ecs_event_to_graph is None:
        raise NotImplementedError("ecs_event_to_graph is not available")

    nodes, edges = ecs_event_to_graph(event)
    for node in nodes:
        add_node(node)
    for edge in edges:
        add_edge(edge)
    return len(nodes), len(edges)


# 入图：批量 ECS 文档
def ingest_ecs_events(events: Iterable[Mapping[str, Any]]) -> Tuple[int, int]:
    """Ingest multiple ECS events."""
    if ecs_event_to_graph is None:
        raise NotImplementedError("ecs_event_to_graph is not available")

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


# 从 OpenSearch 拉取并入图
def ingest_from_opensearch(
    query: Mapping[str, Any] | None = None,
    *,
    size: int = 100,
    include_events: bool = True,
    include_raw_findings: bool = False,
    include_canonical_findings: bool = True,
    date: datetime | None = None,
) -> tuple[int, int, int]:
    # 使用 OpenSearch API 拉取 ECS 事件并写入 Neo4j
    from ..opensearch import INDEX_PATTERNS, get_index_name, index_exists, search

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




def _fetch_edges_inter_nodes(tx, node_uids: List[str], t_start: float, t_end: float) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"t_min": float(t_start), "t_max": float(t_end)}

    # Match each uid into a bound variable.
    match_parts: List[str] = []
    id_parts: List[str] = []
    for idx, uid in enumerate(node_uids):
        alias = f"n{idx}"
        match_parts.append(_match_clause_for_uid(uid, alias, params, f"u{idx}"))
        id_parts.append(f"id({alias})")

    match_clause = "\n".join(match_parts)
    ids_expr = ", ".join(id_parts)

    cypher = (
        f"{match_clause}\n"
        f"WITH [{ids_expr}] AS node_ids\n"
        "MATCH (s)-[r]->(t)\n"
        "WHERE id(s) IN node_ids AND id(t) IN node_ids\n"
        "AND coalesce(r.ts_float, 0.0) >= $t_min AND coalesce(r.ts_float, 0.0) <= $t_max\n"
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    return list(tx.run(cypher, **params))
