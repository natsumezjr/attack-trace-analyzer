from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha1
from typing import Any, Mapping


class NodeType(str, Enum):
    HOST = "Host"
    USER = "User"
    PROCESS = "Process"
    FILE = "File"
    IP = "IP"
    DOMAIN = "Domain"
    NETCON = "NetConn"


class RelType(str, Enum):
    LOGON = "LOGON"
    SPAWNED = "SPAWNED"
    ACCESSED = "ACCESSED"
    CONNECTED = "CONNECTED"
    RESOLVED = "RESOLVED"
    RESOLVES_TO = "RESOLVES_TO"


NODE_UNIQUE_KEY: dict[NodeType, str] = {
    NodeType.HOST: "host.id",
    NodeType.USER: "user.name",
    NodeType.PROCESS: "process.entity_id",
    NodeType.FILE: "file.path",
    NodeType.IP: "related.ip",
    NodeType.DOMAIN: "dns.question.name",
    NodeType.NETCON: "flow.id",
}


EDGE_TYPE_RULES: dict[RelType, tuple[set[NodeType], set[NodeType]]] = {
    RelType.LOGON: ({NodeType.USER}, {NodeType.HOST}),
    RelType.SPAWNED: ({NodeType.PROCESS}, {NodeType.PROCESS}),
    RelType.ACCESSED: ({NodeType.PROCESS}, {NodeType.FILE}),
    RelType.CONNECTED: ({NodeType.PROCESS, NodeType.HOST, NodeType.NETCON}, {NodeType.IP, NodeType.NETCON}),
    RelType.RESOLVED: ({NodeType.HOST}, {NodeType.DOMAIN}),
    RelType.RESOLVES_TO: ({NodeType.DOMAIN}, {NodeType.IP}),
}


def _sha1_hex(raw: str) -> str:
    return sha1(raw.encode("utf-8")).hexdigest()[:16]


def make_host_id(host_name: str) -> str:
    return f"h-{_sha1_hex(host_name)}"


def make_process_entity_id(host_id: str, pid: int, start_ts: str, executable: str) -> str:
    raw = f"{host_id}:{pid}:{start_ts}:{executable}"
    return f"p-{_sha1_hex(raw)}"


def build_uid(ntype: NodeType, key: Mapping[str, Any]) -> str:
    items = [(k, v) for k, v in key.items() if v is not None]
    if not items:
        raise ValueError("Node key must include at least one field.")
    items.sort(key=lambda kv: kv[0])
    if len(items) == 1:
        k, v = items[0]
        return f"{ntype.value}:{k}={v}"
    payload = ";".join(f"{k}={v}" for k, v in items)
    return f"{ntype.value}:{payload}"


def parse_uid(uid: str) -> tuple[NodeType, dict[str, Any]]:
    if ":" not in uid:
        raise ValueError(f"Invalid uid format: {uid}")
    label_raw, rest = uid.split(":", 1)
    try:
        label = NodeType(label_raw)
    except ValueError as exc:
        raise ValueError(f"Unknown node label in uid: {uid}") from exc

    if "=" in rest:
        key: dict[str, Any] = {}
        for chunk in rest.split(";"):
            if not chunk:
                continue
            k, v = chunk.split("=", 1)
            key[k] = v
        if not key:
            raise ValueError(f"Empty key in uid: {uid}")
        return label, key

    key_field = NODE_UNIQUE_KEY[label]
    return label, {key_field: rest}


@dataclass
class GraphNode:
    ntype: NodeType
    key: dict[str, Any]
    props: dict[str, Any] = field(default_factory=dict)

    @property
    def uid(self) -> str:
        return build_uid(self.ntype, self.key)

    def merged_props(self) -> dict[str, Any]:
        merged = dict(self.props)
        for k, v in self.key.items():
            if v is not None:
                merged.setdefault(k, v)
        return merged


@dataclass
class GraphEdge:
    src_uid: str
    dst_uid: str
    rtype: RelType
    props: dict[str, Any] = field(default_factory=dict)

    def get_ts(self) -> str | None:
        return self.props.get("@timestamp") or self.props.get("ts")

    def get_src_uid(self) -> str:
        return self.src_uid

    def get_dst_uid(self) -> str:
        return self.dst_uid

    def get_rtype(self) -> RelType:
        return self.rtype


def host_node(
    host_id: str | None = None,
    host_name: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if host_id is None and host_name is None:
        raise ValueError("host_id or host_name is required.")
    if host_id is None:
        host_id = make_host_id(host_name)
    node_props = dict(props or {})
    if host_name:
        node_props.setdefault("host.name", host_name)
    return GraphNode(ntype=NodeType.HOST, key={"host.id": host_id}, props=node_props)


def user_node(
    user_name: str | None = None,
    user_id: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if user_name is None and user_id is None:
        raise ValueError("user_name or user_id is required.")
    node_props = dict(props or {})
    if user_name:
        node_props.setdefault("user.name", user_name)
    if user_id:
        node_props.setdefault("user.id", user_id)
    key = {"user.name": user_name} if user_name else {"user.id": user_id}
    return GraphNode(ntype=NodeType.USER, key=key, props=node_props)


def process_node(
    process_entity_id: str | None = None,
    *,
    pid: int | None = None,
    executable: str | None = None,
    command_line: str | None = None,
    name: str | None = None,
    host_id: str | None = None,
    start_time: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if process_entity_id is None:
        if host_id is None or pid is None or executable is None or (start_time is None):
            raise ValueError("process_entity_id or (host_id, pid, executable, start_time) is required.")
        process_entity_id = make_process_entity_id(host_id, pid, start_time, executable)
    node_props = dict(props or {})
    node_props.setdefault("process.entity_id", process_entity_id)
    if pid is not None:
        node_props.setdefault("process.pid", pid)
    if executable:
        node_props.setdefault("process.executable", executable)
    if command_line:
        node_props.setdefault("process.command_line", command_line)
    if name:
        node_props.setdefault("process.name", name)
    if host_id:
        node_props.setdefault("host.id", host_id)
    if start_time:
        node_props.setdefault("process.start", start_time)
    return GraphNode(ntype=NodeType.PROCESS, key={"process.entity_id": process_entity_id}, props=node_props)


def file_node(
    path: str | None = None,
    hash_sha256: str | None = None,
    hash_sha1: str | None = None,
    hash_md5: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if path is None and hash_sha256 is None and hash_sha1 is None and hash_md5 is None:
        raise ValueError("file.path or file.hash.* is required.")
    node_props = dict(props or {})
    if path:
        node_props.setdefault("file.path", path)
    if hash_sha256:
        node_props.setdefault("file.hash.sha256", hash_sha256)
    if hash_sha1:
        node_props.setdefault("file.hash.sha1", hash_sha1)
    if hash_md5:
        node_props.setdefault("file.hash.md5", hash_md5)
    if path:
        key = {"file.path": path}
    elif hash_sha256:
        key = {"file.hash.sha256": hash_sha256}
    elif hash_sha1:
        key = {"file.hash.sha1": hash_sha1}
    else:
        key = {"file.hash.md5": hash_md5}
    return GraphNode(ntype=NodeType.FILE, key=key, props=node_props)


def ip_node(addr: str, props: dict[str, Any] | None = None) -> GraphNode:
    if not addr:
        raise ValueError("ip address is required.")
    node_props = dict(props or {})
    node_props.setdefault("related.ip", addr)
    return GraphNode(ntype=NodeType.IP, key={"related.ip": addr}, props=node_props)


def domain_node(dns_name: str | None = None, url_domain: str | None = None, props: dict[str, Any] | None = None) -> GraphNode:
    if not dns_name and not url_domain:
        raise ValueError("dns.question.name or url.domain is required.")
    node_props = dict(props or {})
    if dns_name:
        node_props.setdefault("dns.question.name", dns_name)
    if url_domain:
        node_props.setdefault("url.domain", url_domain)
    key = {"dns.question.name": dns_name} if dns_name else {"url.domain": url_domain}
    return GraphNode(ntype=NodeType.DOMAIN, key=key, props=node_props)


def netcon_node(
    flow_id: str | None = None,
    community_id: str | None = None,
    source_ip: str | None = None,
    source_port: int | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    transport: str | None = None,
    protocol: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if flow_id is None and community_id is None:
        raise ValueError("flow.id or network.community_id is required.")
    node_props = dict(props or {})
    if flow_id:
        node_props.setdefault("flow.id", flow_id)
    if community_id:
        node_props.setdefault("network.community_id", community_id)
    if source_ip:
        node_props.setdefault("source.ip", source_ip)
    if source_port is not None:
        node_props.setdefault("source.port", source_port)
    if destination_ip:
        node_props.setdefault("destination.ip", destination_ip)
    if destination_port is not None:
        node_props.setdefault("destination.port", destination_port)
    if transport:
        node_props.setdefault("network.transport", transport)
    if protocol:
        node_props.setdefault("network.protocol", protocol)
    key = {"flow.id": flow_id} if flow_id else {"network.community_id": community_id}
    return GraphNode(ntype=NodeType.NETCON, key=key, props=node_props)


NodeOrUid = GraphNode | str


def _uid_of(x: NodeOrUid) -> str:
    return x.uid if isinstance(x, GraphNode) else x


def _ntype_of(x: NodeOrUid) -> NodeType | None:
    if isinstance(x, GraphNode):
        return x.ntype
    if isinstance(x, str):
        try:
            return parse_uid(x)[0]
        except ValueError:
            return None
    return None


def _validate_edge_types(rtype: RelType, src: NodeOrUid, dst: NodeOrUid) -> None:
    src_t = _ntype_of(src)
    dst_t = _ntype_of(dst)
    if src_t is None or dst_t is None:
        return
    rules = EDGE_TYPE_RULES.get(rtype)
    if not rules:
        return
    allowed_src, allowed_dst = rules
    if src_t not in allowed_src or dst_t not in allowed_dst:
        raise ValueError(
            f"Invalid edge types for {rtype.value}: "
            f"{src_t.value} -> {dst_t.value}, "
            f"allowed: {sorted(t.value for t in allowed_src)} -> {sorted(t.value for t in allowed_dst)}"
        )


def make_edge(
    src: NodeOrUid,
    dst: NodeOrUid,
    rtype: RelType,
    props: dict[str, Any] | None = None,
    *,
    ts: str | None = None,
    evidence_event_ids: list[str] | None = None,
    weight: float | None = None,
) -> GraphEdge:
    _validate_edge_types(rtype, src, dst)
    edge_props: dict[str, Any] = dict(props or {})
    if ts is not None:
        edge_props.setdefault("@timestamp", ts)
    if evidence_event_ids is not None:
        edge_props.setdefault("custom.evidence.event_ids", evidence_event_ids)
    if weight is not None:
        edge_props.setdefault("weight", weight)
    return GraphEdge(
        src_uid=_uid_of(src),
        dst_uid=_uid_of(dst),
        rtype=rtype,
        props=edge_props,
    )


def logon(user: GraphNode, host: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(user, host, RelType.LOGON, **kw)


def spawned(parent: GraphNode, child: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(parent, child, RelType.SPAWNED, **kw)


def accessed(proc: GraphNode, file: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(proc, file, RelType.ACCESSED, **kw)


def connected(src: GraphNode, dst: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(src, dst, RelType.CONNECTED, **kw)


def resolved(host: GraphNode, domain: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(host, domain, RelType.RESOLVED, **kw)


def resolves_to(domain: GraphNode, ip: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(domain, ip, RelType.RESOLVES_TO, **kw)


class KillChain:
    nodes_edges: list[dict[str, Any]]

    def __init__(self, nodes_edges: list[dict[str, Any]] | None = None) -> None:
        self.nodes_edges = nodes_edges or []

    def append_node_edge(self, node: GraphNode, edge: GraphEdge | None = None) -> None:
        self.nodes_edges.append({"node": node, "edge": edge})

    def pop_node_edge(self) -> tuple[GraphNode, GraphEdge | None]:
        d = self.nodes_edges.pop()
        return d["node"], d["edge"]

    @classmethod
    def get_kill_chain(cls, alarm_edge: GraphEdge) -> "KillChain":
        path = cls(nodes_edges=[])

        def should_stop(curr_node: GraphNode, curr_edge: GraphEdge, depth: int) -> bool:
            return False

        def should_prune(prev_edge: GraphEdge, curr_edge: GraphEdge, depth: int) -> bool:
            return False

        from graph import api as graph_api

        dst_node = graph_api.get_node(alarm_edge.get_dst_uid())
        src_node = graph_api.get_node(alarm_edge.get_src_uid())
        if dst_node is None or src_node is None:
            return path

        path.append_node_edge(dst_node, edge=None)
        path.append_node_edge(src_node, edge=alarm_edge)

        visited_edge: set[tuple[str, str, str]] = set()

        def dfs(curr_node: GraphNode, curr_edge: GraphEdge, depth: int) -> bool:
            sig = (curr_edge.get_src_uid(), curr_edge.get_dst_uid(), curr_edge.get_rtype().value)
            if sig in visited_edge:
                return False
            visited_edge.add(sig)

            if should_stop(curr_node, curr_edge, depth):
                return True

            all_edges = graph_api.get_edges(curr_node) or []
            incoming = [e for e in all_edges if e.get_dst_uid() == curr_node.uid]
            curr_ts = curr_edge.get_ts()

            for prev_edge in incoming:
                prev_ts = prev_edge.get_ts()
                if curr_ts is None or prev_ts is None:
                    continue
                if prev_ts < curr_ts:
                    if should_prune(prev_edge, curr_edge, depth):
                        continue
                    prev_src_uid = prev_edge.get_src_uid()
                    prev_src_node = graph_api.get_node(prev_src_uid)
                    if prev_src_node is None:
                        continue
                    path.append_node_edge(prev_src_node, edge=prev_edge)
                    if dfs(prev_src_node, prev_edge, depth + 1):
                        return True
                    path.pop_node_edge()
            return False

        dfs(src_node, alarm_edge, depth=0)
        return path
