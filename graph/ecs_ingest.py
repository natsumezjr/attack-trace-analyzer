from __future__ import annotations

from typing import Any, Iterable, Mapping

from graph import models


def _get_in(data: Mapping[str, Any], path: Iterable[str]) -> Any | None:
    cur: Any = data
    for key in path:
        if not isinstance(cur, Mapping) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").split("/")[-1]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _extract_dns_answer_ips(dns: Mapping[str, Any]) -> list[str]:
    answers = _as_list(dns.get("answers"))
    ips: list[str] = []
    for ans in answers:
        if isinstance(ans, Mapping):
            data = ans.get("data") or ans.get("ip")
        else:
            data = ans
        if isinstance(data, str) and data:
            ips.append(data)
    resolved = dns.get("resolved_ip") or dns.get("resolved_ips")
    for item in _as_list(resolved):
        if isinstance(item, str) and item:
            ips.append(item)
    return ips


def _map_file_op(action: str | None) -> str | None:
    if not action:
        return None
    lower = action.lower()
    if any(token in lower for token in ("write", "modify", "create", "delete")):
        return "write"
    if any(token in lower for token in ("read", "open")):
        return "read"
    if "execute" in lower:
        return "execute"
    return action


def ecs_event_to_graph(event: Mapping[str, Any]) -> tuple[list[models.GraphNode], list[models.GraphEdge]]:
    nodes_by_uid: dict[str, models.GraphNode] = {}
    edges: list[models.GraphEdge] = []

    event_block = event.get("event", {}) if isinstance(event.get("event"), Mapping) else {}
    event_kind = event_block.get("kind")
    dataset = event_block.get("dataset") or ""
    event_action = event_block.get("action")
    ts = event.get("@timestamp")
    event_id = event_block.get("id")

    evidence_ids: list[str] | None = None
    if event_kind == "alert":
        evidence_ids = _get_in(event, ["custom", "evidence", "event_ids"])
    if not evidence_ids and event_id:
        evidence_ids = [event_id]

    is_alarm = event_kind == "alert"

    def add_node(node: models.GraphNode | None) -> models.GraphNode | None:
        if node is None:
            return None
        nodes_by_uid[node.uid] = node
        return node

    def add_edge(
        rtype: models.RelType,
        src: models.GraphNode | None,
        dst: models.GraphNode | None,
        props: dict[str, Any] | None = None,
    ) -> None:
        if src is None or dst is None:
            return
        edge_props = dict(props or {})
        if is_alarm:
            edge_props.setdefault("is_alarm", True)
        edge = models.make_edge(
            src,
            dst,
            rtype,
            props=edge_props,
            ts=ts,
            evidence_event_ids=evidence_ids,
        )
        edges.append(edge)

    host_id = _get_in(event, ["host", "id"])
    host_name = _get_in(event, ["host", "name"])
    host_node = add_node(models.host_node(host_id=host_id, host_name=host_name)) if host_id or host_name else None
    if host_id is None and host_node is not None:
        host_id = host_node.key.get("host.id")

    user_id = _get_in(event, ["user", "id"])
    user_name = _get_in(event, ["user", "name"])
    user_node = add_node(models.user_node(user_id=user_id, user_name=user_name)) if user_id or user_name else None

    proc_entity_id = _get_in(event, ["process", "entity_id"])
    proc_pid = _get_in(event, ["process", "pid"])
    proc_exe = _get_in(event, ["process", "executable"])
    proc_cmd = _get_in(event, ["process", "command_line"])
    proc_start = _get_in(event, ["process", "start"]) or _get_in(event, ["process", "start_time"])
    proc_name = _get_in(event, ["process", "name"]) or _basename(proc_exe)

    proc_node: models.GraphNode | None = None
    if proc_entity_id or (host_id and proc_pid is not None and proc_exe and (proc_start or ts)):
        if not proc_entity_id:
            proc_entity_id = models.make_process_entity_id(host_id, int(proc_pid), proc_start or ts, proc_exe)
        proc_props: dict[str, Any] = {}
        if proc_exe:
            proc_props["process.executable"] = proc_exe
        if proc_cmd:
            proc_props["process.command_line"] = proc_cmd
        proc_node = add_node(
            models.process_node(
                process_entity_id=proc_entity_id,
                pid=proc_pid,
                executable=proc_exe,
                command_line=proc_cmd,
                name=proc_name,
                host_id=host_id,
                start_time=proc_start or ts,
                props=proc_props,
            )
        )

    parent_entity_id = _get_in(event, ["process", "parent", "entity_id"])
    parent_pid = _get_in(event, ["process", "parent", "pid"])
    parent_exe = _get_in(event, ["process", "parent", "executable"])
    parent_start = _get_in(event, ["process", "parent", "start"]) or _get_in(event, ["process", "parent", "start_time"])
    parent_name = _get_in(event, ["process", "parent", "name"]) or _basename(parent_exe)

    parent_node: models.GraphNode | None = None
    if parent_entity_id:
        parent_props: dict[str, Any] = {}
        if parent_exe:
            parent_props["process.executable"] = parent_exe
        parent_node = add_node(
            models.process_node(
                process_entity_id=parent_entity_id,
                pid=parent_pid,
                executable=parent_exe,
                name=parent_name,
                host_id=host_id,
                start_time=parent_start,
                props=parent_props,
            )
        )

    file_path = _get_in(event, ["file", "path"])
    file_hash_sha256 = _get_in(event, ["file", "hash", "sha256"])
    file_hash_sha1 = _get_in(event, ["file", "hash", "sha1"])
    file_hash_md5 = _get_in(event, ["file", "hash", "md5"])
    file_node = (
        add_node(
            models.file_node(
                path=file_path,
                hash_sha256=file_hash_sha256,
                hash_sha1=file_hash_sha1,
                hash_md5=file_hash_md5,
            )
        )
        if file_path or file_hash_sha256 or file_hash_sha1 or file_hash_md5
        else None
    )

    dns_name = _get_in(event, ["dns", "question", "name"])
    url_domain = _get_in(event, ["url", "domain"])
    domain_name = dns_name or url_domain
    domain_node = add_node(models.domain_node(dns_name=dns_name, url_domain=url_domain)) if domain_name else None

    src_ip = _get_in(event, ["source", "ip"])
    src_port = _get_in(event, ["source", "port"])
    dst_ip = _get_in(event, ["destination", "ip"])
    dst_port = _get_in(event, ["destination", "port"])
    net_transport = _get_in(event, ["network", "transport"])
    net_protocol = _get_in(event, ["network", "protocol"])
    flow_id = _get_in(event, ["flow", "id"])
    community_id = _get_in(event, ["network", "community_id"])
    ip_node = add_node(models.ip_node(dst_ip)) if dst_ip else None
    netcon_node = (
        add_node(
            models.netcon_node(
                flow_id=flow_id,
                community_id=community_id,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                transport=net_transport,
                protocol=net_protocol,
            )
        )
        if flow_id or community_id
        else None
    )

    if dataset.startswith("hostlog.auth") or "authentication" in _as_list(event_block.get("category")):
        add_edge(models.RelType.LOGON, user_node, host_node)

    if proc_node and parent_node and (dataset.startswith("hostlog.process") or "process" in _as_list(event_block.get("category"))):
        add_edge(models.RelType.SPAWNED, parent_node, proc_node)

    if proc_node and file_node:
        op = _map_file_op(event_action)
        props = {"event.action": op} if op else {}
        add_edge(models.RelType.ACCESSED, proc_node, file_node, props=props)

    if netcon_node is not None:
        if proc_node:
            add_edge(models.RelType.CONNECTED, proc_node, netcon_node)
        elif host_node:
            add_edge(models.RelType.CONNECTED, host_node, netcon_node)
        if ip_node and dst_ip:
            props: dict[str, Any] = {}
            if dst_port is not None:
                props["destination.port"] = dst_port
            add_edge(models.RelType.CONNECTED, netcon_node, ip_node, props=props)
    elif proc_node and ip_node and dst_ip:
        props = {"destination.port": dst_port} if dst_port is not None else {}
        add_edge(models.RelType.CONNECTED, proc_node, ip_node, props=props)

    if host_node and domain_node and (dataset.startswith("netflow.dns") or "dns" in _as_list(event_block.get("type", []))):
        add_edge(models.RelType.RESOLVED, host_node, domain_node)
        dns_block = event.get("dns", {}) if isinstance(event.get("dns"), Mapping) else {}
        for ans_ip in _extract_dns_answer_ips(dns_block):
            ans_ip_node = add_node(models.ip_node(ans_ip))
            add_edge(models.RelType.RESOLVES_TO, domain_node, ans_ip_node)

    return list(nodes_by_uid.values()), edges
