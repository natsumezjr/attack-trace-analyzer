from __future__ import annotations

from typing import Any, Iterable, Mapping

from . import models


_MISSING = object()


def _get_in(data: Mapping[str, Any], path: Iterable[str]) -> Any | None:
    # 同时支持嵌套路径和点号路径的字段获取
    parts = list(path)
    cur: Any = data
    for key in parts:
        if not isinstance(cur, Mapping) or key not in cur:
            cur = _MISSING
            break
        cur = cur[key]
    if cur is not _MISSING:
        return cur
    dotted = ".".join(parts)
    if isinstance(data, Mapping) and dotted in data:
        return data[dotted]
    return None


def _basename(path: str | None) -> str | None:
    # 获取路径的文件名部分
    if not path:
        return None
    return path.replace("\\", "/").split("/")[-1]


def _as_list(value: Any) -> list[Any]:
    # 将值统一为列表形式，便于统一处理
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _norm_set(values: Any) -> set[str]:
    # 标准化字符串集合（小写化）
    result: set[str] = set()
    for item in _as_list(values):
        if isinstance(item, str) and item:
            result.add(item.lower())
    return result


def _extract_dns_answer_ips(event: Mapping[str, Any]) -> list[str]:
    # 从 DNS 结果中抽取解析出的 IP 列表
    answers = _as_list(_get_in(event, ["dns", "answers"]))
    ips: list[str] = []
    for ans in answers:
        if isinstance(ans, Mapping):
            data = ans.get("data") or ans.get("ip")
        else:
            data = ans
        if isinstance(data, str) and data:
            ips.append(data)
    resolved = _get_in(event, ["dns", "resolved_ip"]) or _get_in(event, ["dns", "resolved_ips"])
    for item in _as_list(resolved):
        if isinstance(item, str) and item:
            ips.append(item)
    return ips


def _map_file_op(action: str | None) -> str | None:
    # 将事件动作映射为文件操作类型
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
    # 将 ECS 事件转换为图节点与关系边
    nodes_by_uid: dict[str, models.GraphNode] = {}
    edges: list[models.GraphEdge] = []

    event_kind = _get_in(event, ["event", "kind"])
    if not isinstance(event_kind, str):
        return [], []
    event_kind = event_kind.lower()
    if event_kind not in ("event", "alert"):
        return [], []

    dataset_raw = _get_in(event, ["event", "dataset"])
    dataset = dataset_raw if isinstance(dataset_raw, str) else ""
    event_action = _get_in(event, ["event", "action"])
    event_category_raw = _as_list(_get_in(event, ["event", "category"]))
    event_type_raw = _as_list(_get_in(event, ["event", "type"]))
    event_category = _norm_set(event_category_raw)
    event_type = _norm_set(event_type_raw)
    ts = event.get("@timestamp")
    event_id = _get_in(event, ["event", "id"])
    event_severity = _get_in(event, ["event", "severity"])
    event_outcome = _get_in(event, ["event", "outcome"])
    event_code = _get_in(event, ["event", "code"])
    session_id = _get_in(event, ["session", "id"])

    evidence_ids: list[str] | None = None
    if event_kind == "alert":
        raw_ids = _get_in(event, ["custom", "evidence", "event_ids"])
        evidence_ids = _as_list(raw_ids) if raw_ids else None
    elif event_id:
        evidence_ids = [event_id]

    is_alarm = event_kind == "alert"

    base_edge_props: dict[str, Any] = {}
    if event_id:
        base_edge_props["event.id"] = event_id
    if event_kind:
        base_edge_props["event.kind"] = event_kind
    if dataset:
        base_edge_props["event.dataset"] = dataset
    if event_action:
        base_edge_props["event.action"] = event_action
    if event_category_raw:
        base_edge_props["event.category"] = event_category_raw
    if event_type_raw:
        base_edge_props["event.type"] = event_type_raw
    if event_severity is not None:
        base_edge_props["event.severity"] = event_severity
    if event_outcome:
        base_edge_props["event.outcome"] = event_outcome
    if event_code:
        base_edge_props["event.code"] = event_code
    if session_id:
        base_edge_props["session.id"] = session_id
    if event_kind == "alert":
        alert_fields = {
            "rule.id": _get_in(event, ["rule", "id"]),
            "rule.name": _get_in(event, ["rule", "name"]),
            "rule.ruleset": _get_in(event, ["rule", "ruleset"]),
            "threat.framework": _get_in(event, ["threat", "framework"]),
            "threat.tactic.id": _get_in(event, ["threat", "tactic", "id"]),
            "threat.tactic.name": _get_in(event, ["threat", "tactic", "name"]),
            "threat.technique.id": _get_in(event, ["threat", "technique", "id"]),
            "threat.technique.name": _get_in(event, ["threat", "technique", "name"]),
            "threat.technique.subtechnique.id": _get_in(event, ["threat", "technique", "subtechnique", "id"]),
            "custom.finding.stage": _get_in(event, ["custom", "finding", "stage"]),
            "custom.finding.providers": _get_in(event, ["custom", "finding", "providers"]),
            "custom.finding.fingerprint": _get_in(event, ["custom", "finding", "fingerprint"]),
            "custom.confidence": _get_in(event, ["custom", "confidence"]),
        }
        for key, value in alert_fields.items():
            if value is not None:
                base_edge_props[key] = value

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
        edge_props = dict(base_edge_props)
        if props:
            edge_props.update(props)
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
    user_node = add_node(models.user_node(user_id=user_id, user_name=user_name, host_id=host_id)) if user_id or user_name else None

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

    is_auth = "authentication" in event_category or dataset.startswith("hostlog.auth")
    is_process = "process" in event_category or dataset.startswith("hostlog.process")
    is_file = "file" in event_category or dataset.startswith("hostbehavior.file") or dataset.startswith("hostlog.file_registry")
    is_network = "network" in event_category or dataset.startswith("netflow.")

    dns_name = _get_in(event, ["dns", "question", "name"])
    dns_action = event_action.lower() if isinstance(event_action, str) else ""
    is_dns = bool(dns_name) or "dns" in dns_action or dataset.startswith("netflow.dns")
    url_domain = _get_in(event, ["url", "domain"])
    domain_name = dns_name or url_domain
    domain_node = add_node(models.domain_node(dns_name=dns_name, url_domain=url_domain)) if (is_dns and domain_name) else None

    src_ip = _get_in(event, ["source", "ip"])
    src_port = _get_in(event, ["source", "port"])
    dst_ip = _get_in(event, ["destination", "ip"])
    dst_port = _get_in(event, ["destination", "port"])
    net_transport = _get_in(event, ["network", "transport"])
    net_protocol = _get_in(event, ["network", "protocol"])
    flow_id = _get_in(event, ["flow", "id"])
    community_id = _get_in(event, ["network", "community_id"])

    src_ip_node = add_node(models.ip_node(src_ip)) if (is_network and host_node and src_ip) else None
    flow_node = (
        add_node(
            models.netcon_node(
                flow_id=flow_id,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                transport=net_transport,
                protocol=net_protocol,
            )
        )
        if (is_network and flow_id)
        else None
    )
    community_node = (
        add_node(
            models.netcon_node(
                community_id=community_id,
                transport=net_transport,
                protocol=net_protocol,
            )
        )
        if (is_network and community_id)
        else None
    )
    netcon_node = flow_node or community_node

    if is_auth:
        add_edge(models.RelType.LOGON, user_node, host_node)

    if proc_node and parent_node and is_process:
        add_edge(models.RelType.PARENT_OF, parent_node, proc_node)

    if proc_node and file_node and is_file:
        op = _map_file_op(event_action)
        props = {"op": op} if op else {}
        add_edge(models.RelType.USES, proc_node, file_node, props=props)

    if is_network:
        if flow_node and community_node:
            add_edge(models.RelType.CONNECTED, flow_node, community_node)
        if proc_node and netcon_node:
            add_edge(models.RelType.OWNS, proc_node, netcon_node)
        elif host_node and netcon_node:
            add_edge(models.RelType.OWNS, host_node, netcon_node)
        if host_node and src_ip_node:
            add_edge(models.RelType.OWNS, host_node, src_ip_node)

    if host_node and domain_node and is_dns and (is_network or dataset.startswith("netflow.dns")):
        add_edge(models.RelType.RESOLVED, host_node, domain_node)
        for ans_ip in _extract_dns_answer_ips(event):
            ans_ip_node = add_node(models.ip_node(ans_ip))
            add_edge(models.RelType.RESOLVES_TO, domain_node, ans_ip_node)

    return list(nodes_by_uid.values()), edges
