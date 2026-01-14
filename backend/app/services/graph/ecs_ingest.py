from __future__ import annotations

from typing import Any, Iterable, Mapping

from . import models
from .utils import _parse_ts_to_float


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
    # Backward-compatible fallback for any legacy normalization that used
    # dns.resolved_ip(s). The v2 docs prefer dns.answers[].data.
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

    # 仅允许 Telemetry 与 Canonical Finding 入图（见 32/52）
    event_kind = _get_in(event, ["event", "kind"])
    if not isinstance(event_kind, str):
        return [], []
    event_kind = event_kind.lower()
    if event_kind not in ("event", "alert"):
        return [], []

    # v2 graph: only Telemetry events + Canonical Findings.
    dataset_raw0 = _get_in(event, ["event", "dataset"])
    dataset0 = dataset_raw0 if isinstance(dataset_raw0, str) else ""
    if event_kind == "alert" and dataset0 != "finding.canonical":
        return [], []

    dataset = dataset0
    event_action = _get_in(event, ["event", "action"])
    event_category_raw = _as_list(_get_in(event, ["event", "category"]))
    event_type_raw = _as_list(_get_in(event, ["event", "type"]))
    event_category = _norm_set(event_category_raw)
    event_type = _norm_set(event_type_raw)
    # 文档要求 @timestamp 与 event.id 必填，缺失直接丢弃
    ts_raw = event.get("@timestamp")
    if isinstance(ts_raw, (int, float)):
        ts = str(ts_raw)
    elif isinstance(ts_raw, str) and ts_raw:
        ts = ts_raw
    else:
        return [], []

    event_id = _get_in(event, ["event", "id"])
    if not isinstance(event_id, str) or not event_id:
        return [], []
    event_severity = _get_in(event, ["event", "severity"])
    event_outcome = _get_in(event, ["event", "outcome"])
    event_code = _get_in(event, ["event", "code"])
    session_id = _get_in(event, ["session", "id"])

    evidence_ids: list[str] | None = None
    if event_kind == "alert":
        # Canonical Finding 必须携带证据 event_ids
        raw_ids = _get_in(event, ["custom", "evidence", "event_ids"])
        evidence_ids = [
            item for item in _as_list(raw_ids) if isinstance(item, str) and item
        ]
        if not evidence_ids:
            return [], []
    else:
        evidence_ids = [event_id]

    is_alarm = event_kind == "alert"

    base_edge_props: dict[str, Any] = {}
    # 为时间窗过滤与 GDS 投影准备数值时间戳
    base_edge_props["ts_float"] = _parse_ts_to_float(ts)
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

    is_auth = "authentication" in event_category or dataset == "hostlog.auth"
    is_process = "process" in event_category or dataset == "hostlog.process"
    is_file = "file" in event_category or dataset in ("hostbehavior.file", "hostlog.file_registry")
    is_network = "network" in event_category or dataset.startswith("netflow.")

    dns_name = _get_in(event, ["dns", "question", "name"])
    url_domain = _get_in(event, ["url", "domain"])
    domain_name = dns_name or url_domain

    src_ip = _get_in(event, ["source", "ip"])
    src_port = _get_in(event, ["source", "port"])
    dst_ip = _get_in(event, ["destination", "ip"])
    dst_port = _get_in(event, ["destination", "port"])
    net_transport = _get_in(event, ["network", "transport"])
    net_protocol = _get_in(event, ["network", "protocol"])
    flow_id = _get_in(event, ["flow", "id"])
    community_id = _get_in(event, ["network", "community_id"])

    if is_auth:
        add_edge(models.RelType.LOGON, user_node, host_node)

    # RUNS_ON: Process -> Host (structural edge)
    if proc_node and host_node and is_process:
        add_edge(models.RelType.RUNS_ON, proc_node, host_node)

    # SPAWN: parent -> child (only when parent entity_id is available; do not guess from PID)
    if proc_node and parent_node and is_process:
        add_edge(models.RelType.SPAWN, parent_node, proc_node)

    # FILE_ACCESS
    if is_file and host_id and file_path:
        try:
            file_node2 = add_node(
                models.file_node(
                    host_id=str(host_id),
                    path=str(file_path),
                    hash_sha256=file_hash_sha256,
                    hash_sha1=file_hash_sha1,
                    hash_md5=file_hash_md5,
                )
            )
        except Exception:
            file_node2 = None

        op = _map_file_op(event_action) if isinstance(event_action, str) else None
        props = {"op": op} if op else {}

        if dataset == "hostbehavior.file":
            # hostbehavior.file requires process.entity_id by spec; do not downgrade to Host.
            if proc_node and file_node2:
                add_edge(models.RelType.FILE_ACCESS, proc_node, file_node2, props=props)
        elif dataset == "hostlog.file_registry":
            # hostlog.file_registry allows missing process.entity_id; downgrade to Host->File when needed.
            if proc_node and file_node2:
                add_edge(models.RelType.FILE_ACCESS, proc_node, file_node2, props=props)
            elif host_node and file_node2:
                add_edge(models.RelType.FILE_ACCESS, host_node, file_node2, props=props)
        else:
            if proc_node and file_node2:
                add_edge(models.RelType.FILE_ACCESS, proc_node, file_node2, props=props)

    # HAS_IP: Host -> IP (optional)
    host_ips = _as_list(_get_in(event, ["host", "ip"]))
    if host_node and host_ips:
        for hip in host_ips:
            if isinstance(hip, str) and hip:
                ipn = add_node(models.ip_node(hip))
                add_edge(models.RelType.HAS_IP, host_node, ipn)

    # NET_CONNECT: Host/Process -> IP
    is_flow = dataset == "netflow.flow"
    is_syscall_connect = dataset == "hostbehavior.syscall" and (
        (isinstance(event_action, str) and "connect" in event_action.lower())
        or (isinstance(event_code, str) and event_code.lower() == "connect")
    )
    is_network_alert = event_kind == "alert" and ("network" in event_category)
    if (is_flow or is_syscall_connect or is_network_alert) and dst_ip and host_node:
        dst_ip_node = add_node(models.ip_node(str(dst_ip)))
        props: dict[str, Any] = {}
        if dst_port is not None:
            props["destination.port"] = dst_port
        if net_transport:
            props["network.transport"] = net_transport
        if net_protocol:
            props["network.protocol"] = net_protocol
        if flow_id:
            props["flow.id"] = flow_id
        if community_id:
            props["network.community_id"] = community_id

        if proc_node:
            add_edge(models.RelType.NET_CONNECT, proc_node, dst_ip_node, props=props)
        else:
            add_edge(models.RelType.NET_CONNECT, host_node, dst_ip_node, props=props)

    # DNS_QUERY + RESOLVES_TO
    is_dns_event = dataset == "netflow.dns"
    is_dns_alert = event_kind == "alert" and bool(dns_name) and (isinstance(event_action, str) and ("dns" in event_action.lower()))
    if (is_dns_event or is_dns_alert) and domain_name and host_node:
        domain_node2 = add_node(models.domain_node(domain_name=str(domain_name)))
        src = proc_node or host_node
        props: dict[str, Any] = {}
        dns_qtype = _get_in(event, ["dns", "question", "type"])
        if dns_qtype:
            props["dns.question.type"] = dns_qtype
        dns_rcode = _get_in(event, ["dns", "response_code"])
        if dns_rcode:
            props["dns.response_code"] = dns_rcode
        dns_custom = _get_in(event, ["custom", "dns"])
        if isinstance(dns_custom, Mapping):
            for k in ("entropy", "query_length", "tunnel_score"):
                v = dns_custom.get(k)
                if v is not None:
                    props[f"custom.dns.{k}"] = v

        add_edge(models.RelType.DNS_QUERY, src, domain_node2, props=props)

        for ans_ip in _extract_dns_answer_ips(event):
            if isinstance(ans_ip, str) and ans_ip:
                ans_ip_node = add_node(models.ip_node(ans_ip))
                add_edge(models.RelType.RESOLVES_TO, domain_node2, ans_ip_node)

    return list(nodes_by_uid.values()), edges
