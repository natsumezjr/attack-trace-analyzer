# Neo4j 数据库操作模块
from __future__ import annotations

import math
import os
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

from .models import (
    GraphEdge,
    GraphNode,
    NodeType,
    RelType,
    parse_uid,
)
from .utils import (
    _execute_read,
    _execute_write,
    _node_uid_from_record,
    _param_key,
    _cypher_prop,
    _name_suffix,
)


# =============================================================================
# 节点类型到唯一键字段的映射（用于批量 MERGE）
# =============================================================================

# 每种节点类型的唯一键字段定义
# 用于批量写入时生成 MERGE 语句的键条件
_NODE_TYPE_TO_KEY_FIELDS: dict[NodeType, list[str]] = {
    NodeType.HOST: ["host.id"],
    # NOTE: User 节点的唯一键是“按数据选择”的（见 new-docs/80-规范/84-Neo4j实体图谱规范.md）：
    # - 有 user.id 时：Key = user.id
    # - 缺失 user.id 时：Key = (host.id, user.name)
    # 批量写入时不能对同一 NodeType 混用不同键字段，所以 USER 会在 _merge_nodes_in_batch() 内再分桶处理。
    NodeType.USER: ["user.id"],
    NodeType.PROCESS: ["process.entity_id"],
    NodeType.FILE: ["host.id", "file.path"],
    NodeType.DOMAIN: ["domain.name"],
    NodeType.IP: ["ip"],
}


# =============================================================================
# 全局驱动与 Schema 初始化
# =============================================================================

_DRIVER = None
_SCHEMA_READY = False


def _get_driver():
    """获取/缓存 Neo4j driver"""
    global _DRIVER
    if _DRIVER is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "password")
        _DRIVER = GraphDatabase.driver(uri, auth=(user, password))
    return _DRIVER


def _get_session():
    """获取 session（支持指定数据库）"""
    driver = _get_driver()
    database = os.getenv("NEO4J_DATABASE")
    if database:
        return driver.session(database=database)
    return driver.session()


def ensure_schema() -> None:
    """初始化约束与索引（只执行一次）"""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _get_session() as session:
        _execute_write(session, _create_schema)
    _SCHEMA_READY = True


def _create_schema(tx) -> None:
    """创建 v2 schema 约束与索引"""
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


# =============================================================================
# CRUD 操作
# =============================================================================

# =============================================================================
# 批量操作辅助函数
# =============================================================================

def _group_nodes_by_type(
    nodes: Sequence[GraphNode],
) -> dict[NodeType, list[GraphNode]]:
    """按节点类型分组

    Args:
        nodes: 节点列表

    Returns:
        dict[NodeType, list[GraphNode]]: 按类型分组的节点字典

    Examples:
        >>> nodes = [host_node(host_id="h-001"), user_node(user_id="u-001")]
        >>> grouped = _group_nodes_by_type(nodes)
        >>> len(grouped[NodeType.HOST])
        1
        >>> len(grouped[NodeType.USER])
        1
    """
    grouped: dict[NodeType, list[GraphNode]] = {}
    for node in nodes:
        grouped.setdefault(node.ntype, []).append(node)
    return grouped


def _build_unwind_params(
    nodes: list[GraphNode],
    key_fields: list[str],
) -> list[dict[str, Any]]:
    """构建 UNWIND 批量参数

    每个节点转换为扁平结构:
    单键: {"key_val": "h-001", "props": {...}}
    复合键: {"key_0": "h-001", "key_1": "/etc/passwd", "props": {...}}

    Args:
        nodes: 同类型的节点列表
        key_fields: 唯一键字段列表

    Returns:
        list[dict]: UNWIND 参数列表

    Examples:
        >>> nodes = [host_node(host_id="h-001", host_name="victim-01")]
        >>> params = _build_unwind_params(nodes, ["host.id"])
        >>> params[0]["key_val"]
        'h-001'
        >>> params[0]["props"]["host.name"]
        'victim-01'
    """
    items = []
    for node in nodes:
        param = {"props": node.merged_props()}
        # 提取键值到扁平结构
        for i, key_field in enumerate(key_fields):
            if key_field not in node.key:
                raise KeyError(
                    f"Node key missing required field '{key_field}' for batch MERGE; "
                    f"ntype={node.ntype.value} key={node.key}"
                )
            if len(key_fields) == 1:
                param["key_val"] = node.key[key_field]
            else:
                param[f"key_{i}"] = node.key[key_field]
        items.append(param)
    return items


def _build_batch_merge_cypher(label: NodeType, key_fields: list[str]) -> str:
    """生成批量 MERGE Cypher 语句

    单键:   UNWIND $nodes AS node
            MERGE (n:Label {key_field: node.key_val})
            SET n += node.props

    复合键: UNWIND $nodes AS node
            MERGE (n:Label {key1: node.key_0, key2: node.key_1})
            SET n += node.props

    Args:
        label: 节点类型
        key_fields: 唯一键字段列表

    Returns:
        str: Cypher 查询语句

    Examples:
        >>> cypher = _build_batch_merge_cypher(NodeType.HOST, ["host.id"])
        >>> "UNWIND $nodes AS node" in cypher
        True
        >>> "MERGE (n:Host" in cypher
        True
        >>> "node.key_val" in cypher
        True
    """
    if len(key_fields) == 1:
        # 单键: host.id, process.entity_id, etc.
        key_clause = f"{_cypher_prop(key_fields[0])}: node.key_val"
    else:
        # 复合键: (host.id, file.path), (host.id, user.name), etc.
        key_clause = ", ".join(
            f"{_cypher_prop(key_fields[i])}: node.key_{i}"
            for i in range(len(key_fields))
        )

    return f"UNWIND $nodes AS node " \
           f"MERGE (n:{label.value} {{{key_clause}}}) " \
           f"SET n += node.props"


# =============================================================================
# 单条操作 API（向后兼容）
# =============================================================================

def add_node(node: GraphNode) -> None:
    """写入节点（基于唯一键 MERGE）"""
    ensure_schema()
    with _get_session() as session:
        _execute_write(session, _merge_node, node)


def _merge_node(tx, node: GraphNode) -> None:
    """MERGE 节点事务函数"""
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


def add_edge(edge: GraphEdge) -> None:
    """写入关系边（按 event.id 幂等 MERGE）

    关键：为 Phase B 的窗口过滤和 GDS 投影，写入数值时间戳 r.ts_float。

    Args:
        edge: 要写入的边

    Raises:
        ValueError: 当 edge 的 src_uid 或 dst_uid 格式无效时
        Neo4jError: 当数据库写入失败时
    """
    from .utils import _parse_ts_to_float

    ensure_schema()

    # Best-effort: store a numeric timestamp for window/GDS queries.
    # 如果时间戳解析失败，边仍然可以写入，只是没有 ts_float 优化字段。
    if isinstance(getattr(edge, "props", None), dict):
        ts_float = edge.props.get("ts_float")
        if not isinstance(ts_float, (int, float)):
            ts = edge.get_ts() if hasattr(edge, "get_ts") else None
            if ts is not None:
                edge.props["ts_float"] = _parse_ts_to_float(str(ts))

    with _get_session() as session:
        _execute_write(session, _create_edge, edge)


def _create_edge(tx, edge: GraphEdge) -> None:
    """MERGE 边事务函数（按 (src,dst,rtype,event.id) 幂等）"""
    src_label, src_key = parse_uid(edge.src_uid)
    dst_label, dst_key = parse_uid(edge.dst_uid)

    event_id = None
    if isinstance(getattr(edge, "props", None), dict):
        event_id = edge.props.get("event.id")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("edge.props['event.id'] is required for idempotent edge writes")

    params: Dict[str, Any] = {"props": edge.props, "event_id": event_id}

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
        f"MERGE (s)-[r:{edge.rtype.value} {{{_cypher_prop('event.id')}: $event_id}}]->(d) "
        "SET r += $props"
    )
    tx.run(cypher, **params)


# =============================================================================
# 批量操作 API（性能优化）
# =============================================================================

def _merge_nodes_in_batch(tx, nodes: Sequence[GraphNode]) -> int:
    """批量 MERGE 节点事务函数（使用 UNWIND）

    性能优化：
    - 按节点类型分组
    - 每种类型使用 UNWIND 批量 MERGE
    - 减少 Cypher 执行次数和网络往返

    Args:
        tx: Neo4j 事务对象
        nodes: 节点序列

    Returns:
        int: 写入的节点数

    Examples:
        >>> nodes = [host_node(host_id="h-001"), user_node(user_id="u-001")]
        >>> count = _merge_nodes_in_batch(tx, nodes)
        >>> count
        2
    """
    if not nodes:
        return 0

    def _key_fields_for_node(node: GraphNode) -> list[str]:
        # User keys are polymorphic by spec: prefer user.id; fallback to (host.id, user.name).
        if node.ntype == NodeType.USER:
            if "user.id" in node.key:
                return ["user.id"]
            return ["host.id", "user.name"]
        return _NODE_TYPE_TO_KEY_FIELDS[node.ntype]

    # 按 (节点类型, 唯一键字段) 分组
    grouped: dict[tuple[NodeType, tuple[str, ...]], list[GraphNode]] = {}
    for node in nodes:
        key_fields = tuple(_key_fields_for_node(node))
        grouped.setdefault((node.ntype, key_fields), []).append(node)
    total_count = 0

    for (ntype, key_fields_tuple), node_list in grouped.items():
        key_fields = list(key_fields_tuple)

        # 构建 UNWIND 参数
        params_list = _build_unwind_params(node_list, key_fields)

        # 生成 Cypher
        cypher = _build_batch_merge_cypher(ntype, key_fields)

        # 执行批量 MERGE
        tx.run(cypher, nodes=params_list)
        total_count += len(node_list)

    return total_count


def _merge_edges_in_batch(tx, edges: Sequence[GraphEdge]) -> int:
    """批量 MERGE 边事务函数（在单个事务中逐个 MERGE）

    边需要匹配起终点（复合键），复杂度高，保持逐个 MERGE。
    但在单个事务中执行，避免多次 session 创建和网络往返。

    Args:
        tx: Neo4j 事务对象
        edges: 边序列

    Returns:
        int: 写入的边数

    Raises:
        ValueError: 当边缺少 event.id 时

    Examples:
        >>> nodes = [user_node(user_id="u-001"), host_node(host_id="h-001")]
        >>> edge = make_edge(nodes[0], nodes[1], RelType.LOGON, {"event.id": "evt-001"})
        >>> count = _merge_edges_in_batch(tx, [edge])
        >>> count
        1
    """
    if not edges:
        return 0

    from .utils import _parse_ts_to_float

    count = 0
    for edge in edges:
        # 确保有 ts_float 字段（与 add_edge 保持一致）
        if isinstance(edge.props, dict):
            ts_float = edge.props.get("ts_float")
            if not isinstance(ts_float, (int, float)):
                ts = edge.get_ts() if hasattr(edge, "get_ts") else None
                if ts is not None:
                    edge.props["ts_float"] = _parse_ts_to_float(str(ts))

        # 使用现有的 _create_edge 逻辑
        _create_edge(tx, edge)
        count += 1

    return count


def add_nodes_and_edges(
    nodes: Sequence[GraphNode],
    edges: Sequence[GraphEdge],
) -> tuple[int, int]:
    """批量写入节点和边（在单个事务中）

    性能优化：
    - 节点使用 UNWIND 批量 MERGE，减少 Cypher 执行次数
    - 边在单个事务中逐个 MERGE，减少网络往返
    - 预期 1000 事件从 ~16000 次往返降至 ~160 次（100x 提升）

    Args:
        nodes: 节点列表（去重由 MERGE 保证）
        edges: 边列表（按 event.id 幂等）

    Returns:
        tuple[int, int]: (节点数, 边数)

    Raises:
        Neo4jError: 当数据库写入失败时

    Examples:
        >>> nodes = [host_node(host_id="h-001"), user_node(user_id="u-001")]
        >>> edges = [logon_edge(user, host)]
        >>> add_nodes_and_edges(nodes, edges)
        (2, 1)

    Notes:
        - 节点按唯一键自动去重（MERGE 语义）
        - 边按 (src, dst, rtype, event.id) 四元组去重
        - 保持与 add_node() / add_edge() 相同的幂等性

    See Also:
        add_node: 单节点写入 API（向后兼容）
        add_edge: 单边写入 API（向后兼容）
    """
    ensure_schema()

    try:
        with _get_session() as session:
            node_count = _execute_write(session, _merge_nodes_in_batch, nodes)
            edge_count = _execute_write(session, _merge_edges_in_batch, edges)
        return node_count, edge_count
    except Neo4jError as exc:
        # 提供详细的错误上下文
        raise Neo4jError(
            f"Failed to batch write {len(nodes)} nodes and {len(edges)} edges: {exc}"
        ) from exc


# =============================================================================
# 查询操作
# =============================================================================

def get_node(uid: str) -> Optional[GraphNode]:
    """按 UID 查询单个节点

    Args:
        uid: 节点 UID（格式："NodeType:key=value"）

    Returns:
        GraphNode: 节点实例，如果不存在则返回 None

    Raises:
        ValueError: 当 uid 格式无效时
    """
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
    """查询单个节点的事务函数"""
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


def get_edges(node: GraphNode) -> List[GraphEdge]:
    """查询节点相关边

    Args:
        node: 节点实例

    Returns:
        List[GraphEdge]: 相关边的列表
    """
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
    """查询节点相关边的事务函数"""
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


def get_graph_by_attack_id(attack_id: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
    """按 ATT&CK ID 查询子图（节点 + 边）

    Args:
        attack_id: ATT&CK tactic ID 或 technique ID（如 TA0001 / T1059）

    Returns:
        Tuple[List[GraphNode], List[GraphEdge]]: 去重后的节点列表与边列表
    """
    if not isinstance(attack_id, str) or not attack_id.strip():
        return [], []
    with _get_session() as session:
        rows = _execute_read(session, _fetch_graph_by_attack_id, attack_id.strip())

    nodes_by_uid: Dict[str, GraphNode] = {}
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

        for uid, labels, props in (
            (src_uid, row["src_labels"], row["src_props"]),
            (dst_uid, row["dst_labels"], row["dst_props"]),
        ):
            if uid in nodes_by_uid:
                continue
            ntype, key = parse_uid(uid)
            node_props = dict(props)
            for k in key:
                node_props.pop(k, None)
            nodes_by_uid[uid] = GraphNode(ntype=ntype, key=key, props=node_props)

    return list(nodes_by_uid.values()), edges


def _fetch_graph_by_attack_id(tx, attack_id: str) -> List[Dict[str, Any]]:
    """按 ATT&CK ID 查询子图的事务函数"""
    cypher = (
        "MATCH ()-[r]->() "
        "WHERE r.`threat.technique.id` = $attack_id "
        "OR r.`threat.tactic.id` = $attack_id "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    return list(tx.run(cypher, attack_id=attack_id))


def get_alarm_edges() -> List[GraphEdge]:
    """查询所有告警边（is_alarm = true 的边）

    Returns:
        List[GraphEdge]: 告警边的列表
    """
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
    """查询告警边的事务函数"""
    cypher = (
        "MATCH ()-[r]->() "
        "WHERE coalesce(r.is_alarm, false) = true "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    return list(tx.run(cypher))


def get_edges_in_window(
    *,
    t_min: float,
    t_max: float,
    allowed_reltypes: Optional[Sequence[str]] = None,
    only_alarm: bool = False,
) -> List[GraphEdge]:
    """按时间窗查询边集合（可选关系类型/告警过滤）

    Args:
        t_min: 时间窗口起始时间（Unix 时间戳，秒）
        t_max: 时间窗口结束时间（Unix 时间戳，秒）
        allowed_reltypes: 允许的关系类型列表，None 表示允许所有类型
        only_alarm: 是否只返回告警边

    Returns:
        List[GraphEdge]: 时间窗口内的边列表
    """
    with _get_session() as session:
        rows = _execute_read(
            session,
            _fetch_edges_in_window,
            float(t_min),
            float(t_max),
            allowed_reltypes,
            only_alarm,
        )

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
        edges.append(
            GraphEdge(
                src_uid=src_uid,
                dst_uid=dst_uid,
                rtype=rtype,
                props=dict(row["rprops"]),
            )
        )
    return edges


def get_edges_by_task_id(
    *,
    task_id: str,
    only_path: bool = False,
) -> List[GraphEdge]:
    """按 analysis.task_id 查询边集合（可选仅关键路径边）"""
    # #region agent log
    print(f"[DEBUG] get_edges_by_task_id entry: task_id={task_id}, only_path={only_path}")
    # #endregion
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("task_id is required")

    # #region agent log
    print(f"[DEBUG] ensuring schema...")
    # #endregion
    ensure_schema()
    # #region agent log
    print(f"[DEBUG] getting session...")
    # #endregion
    try:
        with _get_session() as session:
            # #region agent log
            print(f"[DEBUG] executing read transaction...")
            # #endregion
            rows = _execute_read(session, _fetch_edges_by_task_id, task_id, bool(only_path))
            # #region agent log
            print(f"[DEBUG] query returned {len(rows)} rows")
            # #endregion
    except Exception as e:
        # #region agent log
        print(f"[DEBUG] EXCEPTION in get_edges_by_task_id session/query: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        # #endregion
        raise

    edges: List[GraphEdge] = []
    for i, row in enumerate(rows):
        # #region agent log
        print(f"[DEBUG] processing row {i+1}/{len(rows)}")
        # #endregion
        try:
            src_uid = _node_uid_from_record(row["src_labels"], row["src_props"])
            dst_uid = _node_uid_from_record(row["dst_labels"], row["dst_props"])
            # #region agent log
            print(f"[DEBUG] row {i+1}: src_uid={src_uid}, dst_uid={dst_uid}")
            # #endregion
            if src_uid is None or dst_uid is None:
                # #region agent log
                print(f"[DEBUG] row {i+1}: skipping due to None uid")
                # #endregion
                continue
            try:
                rtype = RelType(row["rtype"])
            except ValueError as e:
                # #region agent log
                print(f"[DEBUG] row {i+1}: RelType ValueError: {e}, rtype={row.get('rtype')}")
                # #endregion
                continue
            edges.append(GraphEdge(src_uid=src_uid, dst_uid=dst_uid, rtype=rtype, props=dict(row["rprops"])))
        except Exception as e:
            # #region agent log
            print(f"[DEBUG] EXCEPTION processing row {i+1}: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            # #endregion
            continue
    # #region agent log
    print(f"[DEBUG] get_edges_by_task_id returning {len(edges)} edges")
    # #endregion
    return edges


def _fetch_edges_by_task_id(tx, task_id: str, only_path: bool) -> List[Dict[str, Any]]:
    """按 analysis.task_id 查询边的事务函数"""
    # #region agent log
    print(f"[DEBUG] _fetch_edges_by_task_id: task_id={task_id}, only_path={only_path}")
    # #endregion
    params: Dict[str, Any] = {"task_id": task_id, "only_path": bool(only_path)}

    cypher = (
        "MATCH ()-[r]->() "
        f"WHERE r.{_cypher_prop('analysis.task_id')} = $task_id "
        "AND (NOT $only_path OR coalesce(r.`analysis.is_path_edge`, false) = true) "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(startNode(r)) AS src_labels, properties(startNode(r)) AS src_props, "
        "labels(endNode(r)) AS dst_labels, properties(endNode(r)) AS dst_props"
    )
    # #region agent log
    print(f"[DEBUG] executing cypher query: {cypher[:100]}...")
    print(f"[DEBUG] with params: {params}")
    # #endregion
    try:
        result = list(tx.run(cypher, **params))
        # #region agent log
        print(f"[DEBUG] cypher query returned {len(result)} results")
        # #endregion
        return result
    except Exception as e:
        # #region agent log
        print(f"[DEBUG] EXCEPTION in _fetch_edges_by_task_id cypher: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        # #endregion
        raise


def _fetch_edges_in_window(
    tx,
    t_min: float,
    t_max: float,
    allowed_reltypes: Optional[Sequence[str]],
    only_alarm: bool,
) -> List[Dict[str, Any]]:
    """时间窗查询的事务函数"""
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


def get_graph_for_frontend(
    *,
    node_size: int = 36,
    node_spacing: int = 160,
) -> Dict[str, Any]:
    """返回前端绘图用的全量图数据（nodes + edges）。

    节点与边信息来自 Neo4j 全量查询，坐标为简单网格布局。
    """
    ensure_schema()
    with _get_session() as session:
        node_rows = _execute_read(session, _fetch_all_nodes)
        edge_rows = _execute_read(session, _fetch_all_edges)

    nodes_by_uid: Dict[str, GraphNode] = {}
    for row in node_rows:
        uid = _node_uid_from_record(row["labels"], row["props"])
        if uid is None or uid in nodes_by_uid:
            continue
        ntype, key = parse_uid(uid)
        node_props = dict(row["props"])
        for k in key:
            node_props.pop(k, None)
        nodes_by_uid[uid] = GraphNode(ntype=ntype, key=key, props=node_props)

    edges: List[GraphEdge] = []
    for row in edge_rows:
        src_uid = _node_uid_from_record(row["src_labels"], row["src_props"])
        dst_uid = _node_uid_from_record(row["dst_labels"], row["dst_props"])
        if src_uid is None or dst_uid is None:
            continue
        try:
            rtype = RelType(row["rtype"])
        except ValueError:
            continue
        edges.append(GraphEdge(src_uid=src_uid, dst_uid=dst_uid, rtype=rtype, props=dict(row["rprops"])))

    nodes_list = list(nodes_by_uid.values())
    total_nodes = len(nodes_list)
    cols = max(1, int(math.sqrt(total_nodes)))

    def _icon_key(ntype: NodeType) -> str:
        mapping = {
            NodeType.HOST: "host",
            NodeType.USER: "user",
            NodeType.PROCESS: "process",
            NodeType.FILE: "file",
            NodeType.IP: "ip",
            NodeType.DOMAIN: "domain",
        }
        return mapping.get(ntype, "node")

    frontend_nodes: List[Dict[str, Any]] = []
    for idx, node in enumerate(nodes_list):
        x = (idx % cols) * node_spacing + node_spacing // 2
        y = (idx // cols) * node_spacing + node_spacing // 2
        frontend_nodes.append(
            {
                "id": node.uid,
                "ntype": node.ntype.value,
                "type": "image",
                "style": {
                    "x": x,
                    "y": y,
                    "size": node_size,
                    "src": _icon_key(node.ntype),
                },
            }
        )

    frontend_edges: List[Dict[str, Any]] = []
    for idx, edge in enumerate(edges):
        frontend_edges.append(
            {
                "id": f"edge-{idx + 1}",
                "type": edge.rtype.value,
                "source": edge.src_uid,
                "target": edge.dst_uid,
            }
        )

    return {
        "data": {
            "nodes": frontend_nodes,
            "edges": frontend_edges,
        },
        "behaviors": ["drag-canvas", "zoom-canvas", "drag-element"],
    }


def _fetch_all_nodes(tx) -> List[Dict[str, Any]]:
    """查询全部节点的事务函数"""
    cypher = "MATCH (n) RETURN labels(n) AS labels, properties(n) AS props"
    return list(tx.run(cypher))


def _fetch_all_edges(tx) -> List[Dict[str, Any]]:
    """查询全部边的事务函数"""
    cypher = (
        "MATCH (s)-[r]->(t) "
        "RETURN type(r) AS rtype, properties(r) AS rprops, "
        "labels(s) AS src_labels, properties(s) AS src_props, "
        "labels(t) AS dst_labels, properties(t) AS dst_props"
    )
    return list(tx.run(cypher))


# =============================================================================
# GDS 算法
# =============================================================================

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
    """使用 Neo4j GDS 计算时间窗内的加权最短路径

    Args:
        src_uid: 源节点 UID
        dst_uid: 目标节点 UID
        t_min: 时间窗口起始时间（Unix 时间戳，秒）
        t_max: 时间窗口结束时间（Unix 时间戳，秒）
        risk_weights: 关系类型到风险权重的映射
        min_risk: 最小风险阈值，低于此值的边将被过滤
        allowed_reltypes: 允许的关系类型列表，None 表示允许所有类型

    Returns:
        Optional[Tuple[float, List[GraphEdge]]]: (总成本, 边列表)，如果路径不存在则返回 None
    """
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
    """为 UID 生成 MATCH 子句"""
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
    """GDS 最短路算法的事务函数"""
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
    """生成节点 ID 对之间重建边的 Cypher 查询"""
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


# =============================================================================
# 分析结果写回
# =============================================================================

def close() -> None:
    """关闭 Neo4j driver 连接"""
    global _DRIVER
    if _DRIVER is None:
        return
    _DRIVER.close()
    _DRIVER = None


def set_analysis_task_id(target: GraphNode | GraphEdge | str, task_id: str) -> int:
    """Set analysis.task_id on a node or edge."""
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    ensure_schema()
    with _get_session() as session:
        if isinstance(target, GraphEdge):
            return _execute_write(session, _set_analysis_task_id_edge_tx, target, task_id)
        if isinstance(target, GraphNode):
            uid = target.uid
        elif isinstance(target, str):
            uid = target
        else:
            raise ValueError("target must be a GraphNode, GraphEdge, or node uid string")
        return _execute_write(session, _set_analysis_task_id_node_tx, uid, task_id)


def _set_analysis_task_id_node_tx(tx, uid: str, task_id: str) -> int:
    """Set analysis.task_id on a single node."""
    label, key = parse_uid(uid)
    params: Dict[str, Any] = {"task_id": task_id}

    clause_parts = []
    for k, v in key.items():
        param = _param_key(k)
        clause_parts.append(f"{_cypher_prop(k)}: ${param}")
        params[param] = v
    clause = ", ".join(clause_parts)

    cypher = (
        f"MATCH (n:{label.value} {{{clause}}}) "
        f"SET n.{_cypher_prop('analysis.task_id')} = $task_id "
        "RETURN count(n) AS cnt"
    )
    record = tx.run(cypher, **params).single()
    if record is None:
        return 0
    count = record.get("cnt")
    return int(count) if isinstance(count, (int, float)) else 0


def _set_analysis_task_id_edge_tx(tx, edge: GraphEdge, task_id: str) -> int:
    """Set analysis.task_id on a single edge."""
    if not isinstance(edge.props, dict):
        return 0
    event_id = edge.props.get("event.id")
    if not isinstance(event_id, str) or not event_id:
        return 0

    src_label, src_key = parse_uid(edge.src_uid)
    dst_label, dst_key = parse_uid(edge.dst_uid)

    params: Dict[str, Any] = {"event_id": event_id, "task_id": task_id}

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
        f"MATCH (s:{src_label.value} {{{src_clause}}})-[r:{edge.rtype.value}]->(t:{dst_label.value} {{{dst_clause}}}) "
        f"WHERE r.{_cypher_prop('event.id')} = $event_id "
        f"SET r.{_cypher_prop('analysis.task_id')} = $task_id "
        "RETURN count(r) AS cnt"
    )
    record = tx.run(cypher, **params).single()
    if record is None:
        return 0
    count = record.get("cnt")
    return int(count) if isinstance(count, (int, float)) else 0


def write_analysis_results(
    edges: Sequence[GraphEdge],
    *,
    task_id: str,
    updated_at: str,
) -> int:
    """写回溯源结果到边属性（analysis.* 覆盖语义）"""
    if not edges:
        return 0
    ensure_schema()
    total_updated = 0
    with _get_session() as session:
        for edge in edges:
            total_updated += _execute_write(session, _write_analysis_result_tx, edge, task_id, updated_at)
    return total_updated


def _write_analysis_result_tx(tx, edge: GraphEdge, task_id: str, updated_at: str) -> int:
    """写回单条分析结果的事务函数"""
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
    """从边属性提取分析结果属性"""
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
