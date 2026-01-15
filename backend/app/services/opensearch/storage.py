# OpenSearch 存储相关功能（数据路由、批量存储、去重）

import hashlib
import json
from typing import Any

from app.core.time import parse_datetime, to_rfc3339, utc_now_rfc3339

from .client import bulk_index, get_document, refresh_index
from .index import INDEX_PATTERNS, get_index_name

# ATT&CK Tactic 映射表（从 analysis.py 导入，用于标签转换）
try:
    from .analysis import (
        TACTIC_NAME_TO_ID_MAP,
        TACTIC_ID_TO_NAME_MAP,
        TECHNIQUE_TO_TACTIC_MAP,
        _get_tactic_id_from_name,
        _get_tactic_name,
        _get_tactic_from_technique,
    )
except ImportError:
    # 如果导入失败，定义基本映射（避免循环导入）
    TACTIC_NAME_TO_ID_MAP = {
        "initial_access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege_escalation": "TA0004",
        "defense_evasion": "TA0005",
        "credential_access": "TA0006",
        "discovery": "TA0007",
        "lateral_movement": "TA0008",
        "collection": "TA0009",
        "command_and_control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }
    
    TACTIC_ID_TO_NAME_MAP = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact",
    }
    
    TECHNIQUE_TO_TACTIC_MAP = {
        # Initial Access (TA0001)
        "T1078": "TA0001",  # Valid Accounts
        "T1190": "TA0001",  # Exploit Public-Facing Application
        # Execution (TA0002)
        "T1059": "TA0002",  # Command and Scripting Interpreter
        "T1106": "TA0002",  # Native API
        # Persistence (TA0003)
        "T1546": "TA0003",  # Event Triggered Execution
        "T1547": "TA0003",  # Boot or Logon Autostart Execution
        "T1133": "TA0003",  # External Remote Services
        # Privilege Escalation (TA0004)
        "T1055": "TA0004",  # Process Injection
        "T1548": "TA0004",  # Abuse Elevation Control Mechanism
        # Defense Evasion (TA0005)
        "T1562": "TA0005",  # Impair Defenses
        "T1070": "TA0005",  # Indicator Removal on Host
        # Credential Access (TA0006)
        "T1003": "TA0006",  # OS Credential Dumping
        "T1110": "TA0006",  # Brute Force
        # Discovery (TA0007)
        "T1083": "TA0007",  # File and Directory Discovery
        "T1018": "TA0007",  # Remote System Discovery
        # Lateral Movement (TA0008)
        "T1021": "TA0008",  # Remote Services
        "T1072": "TA0008",  # Software Deployment Tools
        # Collection (TA0009)
        "T1074": "TA0009",  # Data Staged
        "T1005": "TA0009",  # Data from Local System
        # Exfiltration (TA0010)
        "T1041": "TA0010",  # Exfiltration Over C2 Channel
        "T1020": "TA0010",  # Automated Exfiltration
        "T1048": "TA0010",  # Exfiltration Over Alternative Protocol
        # Command and Control (TA0011)
        "T1071": "TA0011",  # Application Layer Protocol
        "T1095": "TA0011",  # Non-Application Layer Protocol
        # Impact (TA0040)
        "T1531": "TA0040",  # Account Access Removal
        "T1565": "TA0040",  # Data Manipulation
        "T1489": "TA0040",  # Service Stop
    }
    
    def _get_tactic_id_from_name(tactic_name: str) -> str:
        return TACTIC_NAME_TO_ID_MAP.get(tactic_name.lower(), "TA0000")
    
    def _get_tactic_name(tactic_id: str) -> str:
        return TACTIC_ID_TO_NAME_MAP.get(tactic_id, "Unknown")
    
    def _get_tactic_from_technique(technique_id: str) -> str:
        if technique_id in TECHNIQUE_TO_TACTIC_MAP:
            return TECHNIQUE_TO_TACTIC_MAP[technique_id]
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        return TECHNIQUE_TO_TACTIC_MAP.get(base_id, "TA0000")


def _to_rfc3339(value: Any) -> str | None:
    return to_rfc3339(value)


def _extract_timestamp(doc: dict[str, Any]) -> str | None:
    ts = _to_rfc3339(doc.get("@timestamp"))
    if ts:
        return ts

    event_obj = doc.get("event")
    if isinstance(event_obj, dict):
        ts = _to_rfc3339(event_obj.get("created"))
        if ts:
            return ts

    # Legacy/alternate: flattened keys.
    ts = _to_rfc3339(doc.get("event.created"))
    if ts:
        return ts

    return None


def _sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def _dotted_to_nested(doc: dict[str, Any]) -> None:
    """
    Normalize flattened ECS keys (e.g. "event.id") into nested objects.

    Rules (docs/51-ECS字段规范.md):
    - Nested object semantics win when both exist.
    - After a successful merge, the dotted key is removed.
    """
    dotted_keys = [k for k in doc.keys() if isinstance(k, str) and "." in k]
    for dotted in dotted_keys:
        value = doc.get(dotted)
        if value is None:
            continue
        parts = dotted.split(".")
        if len(parts) < 2:
            continue
        cur: Any = doc
        ok = True
        for part in parts[:-1]:
            if not isinstance(cur, dict):
                ok = False
                break
            existing = cur.get(part)
            if existing is None:
                nxt: dict[str, Any] = {}
                cur[part] = nxt
                cur = nxt
                continue
            if isinstance(existing, dict):
                cur = existing
                continue
            ok = False
            break
        if not ok or not isinstance(cur, dict):
            continue
        leaf = parts[-1]
        if leaf not in cur:
            cur[leaf] = value
        doc.pop(dotted, None)


def _ensure_required_fields(doc: dict[str, Any]) -> dict[str, Any] | None:
    """
    Enforce the "公共字段" subset from docs/51-ECS字段规范.md.

    We intentionally do best-effort filling for missing fields when safe:
    - Default/normalize event.kind
    - Normalize event.dataset naming for known legacy values
    - Ensure host.id derived from host.name
    - Ensure ecs.version and event.original/message exist
    """
    event_obj = doc.get("event")
    if not isinstance(event_obj, dict):
        event_obj = {}
        doc["event"] = event_obj

    telemetry_datasets = {
        # Telemetry datasets (docs/81-ECS字段规范.md)
        "hostlog.auth",
        "hostlog.process",
        "hostlog.file_registry",
        "hostbehavior.syscall",
        "hostbehavior.file",
        "hostbehavior.memory",
        "netflow.flow",
        "netflow.dns",
        "netflow.http",
        "netflow.tls",
        "netflow.icmp",
    }
    finding_providers = {"falco", "suricata", "filebeat_sigma", "security_analytics"}

    # event.kind (required; may infer only when missing)
    kind_raw = event_obj.get("kind")
    kind = kind_raw.lower().strip() if isinstance(kind_raw, str) else ""
    if not kind:
        dataset_probe = event_obj.get("dataset")
        if isinstance(dataset_probe, str) and dataset_probe.strip():
            kind = "alert" if dataset_probe.startswith("finding.") else "event"
        else:
            return None
    if kind not in ("event", "alert"):
        return None
    event_obj["kind"] = kind

    # event.dataset (best-effort legacy mapping)
    dataset_raw = event_obj.get("dataset")
    dataset = dataset_raw.strip() if isinstance(dataset_raw, str) else ""
    if not dataset:
        return None
    if kind == "alert":
        if dataset in ("falco", "finding.raw.falco"):
            dataset = "finding.raw.falco"
        elif dataset in ("netflow.alert", "suricata", "finding.raw.suricata"):
            dataset = "finding.raw.suricata"
        elif dataset in ("finding.raw", "filebeat", "sigma", "finding.raw.filebeat_sigma"):
            dataset = "finding.raw.filebeat_sigma"
        elif dataset == "finding.canonical":
            dataset = "finding.canonical"
    else:
        # Telemetry
        if dataset == "falco":
            dataset = "hostbehavior.syscall"

    event_obj["dataset"] = dataset

    # Enforce the dataset whitelist (docs/81-ECS字段规范.md).
    if kind == "event":
        if dataset not in telemetry_datasets:
            return None
    else:
        if dataset == "finding.canonical":
            pass
        elif dataset.startswith("finding.raw."):
            provider = dataset.split("finding.raw.", 1)[1]
            if provider not in finding_providers:
                return None
        else:
            return None

    # ecs.version (fixed)
    ecs_obj = doc.get("ecs")
    if not isinstance(ecs_obj, dict):
        ecs_obj = {}
        doc["ecs"] = ecs_obj
    ecs_obj["version"] = "9.2.0"

    # message (required, default empty string)
    if not isinstance(doc.get("message"), str):
        doc["message"] = doc.get("message") if isinstance(doc.get("message"), str) else ""

    # event.original (required, default empty string)
    if not isinstance(event_obj.get("original"), str):
        event_obj["original"] = ""

    # host.name + host.id (required)
    host_obj = doc.get("host")
    if not isinstance(host_obj, dict):
        host_obj = {}
        doc["host"] = host_obj

    host_name = host_obj.get("name")
    if not isinstance(host_name, str) or not host_name.strip():
        return None
    host_name = host_name.strip()
    host_obj["name"] = host_name

    host_id = host_obj.get("id")
    if not isinstance(host_id, str) or not host_id.strip():
        host_obj["id"] = f"h-{_sha1_hex(host_name)[:16]}"

    # event.id (idempotency key)
    event_id = event_obj.get("id")
    if not isinstance(event_id, str) or not event_id.strip():
        # Cannot safely backfill a stable id without the raw payload bytes
        # (docs/81-ECS字段规范.md: event.id = evt- + sha1(raw_payload_bytes)[:16]).
        # Client-side pull API is responsible for generating stable event.id.
        return None

    # Finding-only required fields (minimum set for downstream graph & dedup)
    if kind == "alert":
        custom_obj = doc.get("custom")
        if not isinstance(custom_obj, dict):
            custom_obj = {}
            doc["custom"] = custom_obj

        finding_obj = custom_obj.get("finding")
        if not isinstance(finding_obj, dict):
            finding_obj = {}
            custom_obj["finding"] = finding_obj

        stage = "canonical" if dataset == "finding.canonical" else "raw"
        finding_obj["stage"] = stage

        if stage == "raw":
            provider = None
            if dataset.startswith("finding.raw."):
                provider = dataset.split("finding.raw.", 1)[1]
            if provider:
                finding_obj["providers"] = [provider]

        evidence_obj = custom_obj.get("evidence")
        if not isinstance(evidence_obj, dict):
            evidence_obj = {}
            custom_obj["evidence"] = evidence_obj

        raw_ids = evidence_obj.get("event_ids")
        if not isinstance(raw_ids, list):
            raw_ids = []
        evidence_ids = [
            item
            for item in raw_ids
            if isinstance(item, str) and item and item.strip().lower() not in ("unknown", "n/a")
        ]
        if not evidence_ids:
            evidence_ids = [event_obj["id"]]
        evidence_obj["event_ids"] = evidence_ids

        sev_raw = event_obj.get("severity")
        sev = None
        if isinstance(sev_raw, bool):
            sev = None
        elif isinstance(sev_raw, (int, float)):
            sev = int(sev_raw)
        elif isinstance(sev_raw, str) and sev_raw.strip().isdigit():
            sev = int(sev_raw.strip(), 10)
        if sev is None:
            sev = 50
        event_obj["severity"] = max(0, min(sev, 100))

        # rule.* must exist
        rule_obj = doc.get("rule")
        if not isinstance(rule_obj, dict):
            rule_obj = {}
            doc["rule"] = rule_obj
        if not isinstance(rule_obj.get("name"), str) or not rule_obj.get("name").strip():
            rule_obj["name"] = rule_obj.get("id") if isinstance(rule_obj.get("id"), str) else "Unknown"
        if not isinstance(rule_obj.get("id"), str) or not rule_obj.get("id").strip():
            rule_obj["id"] = f"rule-{_sha1_hex(rule_obj['name'])[:16]}"

        # threat.* defaults
        threat_obj = doc.get("threat")
        if not isinstance(threat_obj, dict):
            threat_obj = {}
            doc["threat"] = threat_obj
        threat_obj.setdefault("framework", "MITRE ATT&CK")
        
        # 从 tags 字段提取 ATT&CK 标签并转换为 threat 信息
        tactic_id = None
        tactic_name = None
        technique_id = None
        
        # 收集所有标签（从文档的 tags 字段和 anomaly.matched_rules[].tags 字段）
        all_tags = []
        
        # 方法1: 从文档顶层的 tags 字段提取（filebeat 格式）
        tags = doc.get('tags', [])
        if isinstance(tags, list):
            all_tags.extend(tags)
        
        # 方法2: 从 anomaly.matched_rules[].tags 字段提取（filebeat 格式）
        anomaly_obj = doc.get('anomaly', {})
        if isinstance(anomaly_obj, dict):
            matched_rules = anomaly_obj.get('matched_rules', [])
            if isinstance(matched_rules, list):
                for rule in matched_rules:
                    if isinstance(rule, dict):
                        rule_tags = rule.get('tags', [])
                        if isinstance(rule_tags, list):
                            all_tags.extend(rule_tags)
        
        # 解析 attack.* 标签
        tactic_name_tags = []
        technique_tags = []
        
        for tag in all_tags:
            if isinstance(tag, str) and tag.startswith('attack.'):
                parts = tag.split('.')
                if len(parts) >= 2:
                    tag_value = parts[1]
                    # 检查是否是 technique ID（如 attack.t1562.001）
                    if tag_value.startswith('t') and len(tag_value) > 1:
                        # 提取完整的 technique ID（包括子技术，如 t1562.001）
                        if len(parts) > 2:
                            technique_tags.append(f"{tag_value}.{'.'.join(parts[2:])}")
                        else:
                            technique_tags.append(tag_value)
                    # 检查是否是 tactic ID（如 attack.ta0005）- 跳过，因为我们需要从名称映射
                    elif tag_value.startswith('ta') and len(tag_value) > 2:
                        continue
                    # 否则是 tactic name（如 attack.defense_evasion）
                    else:
                        tactic_name_tags.append(tag_value)
        
        # 优先使用 tactic name 标签（如果存在）
        if tactic_name_tags:
            for tag_value in tactic_name_tags:
                tactic_id_candidate = _get_tactic_id_from_name(tag_value)
                if tactic_id_candidate and tactic_id_candidate != "TA0000":
                    tactic_id = tactic_id_candidate
                    tactic_name = _get_tactic_name(tactic_id)
                    break
        
        # 提取 technique ID（无论是否已找到 tactic）
        if technique_tags:
            # 取第一个 technique 标签
            tag_value = technique_tags[0]
            # 转换为完整的 technique ID（如 t1562.001 -> T1562.001）
            if tag_value[0] == 't':
                technique_id_candidate = 'T' + tag_value[1:]
            else:
                technique_id_candidate = tag_value.upper()
            technique_id = technique_id_candidate
            
            # 如果没有找到 tactic，从 technique 推断
            if not tactic_id:
                tactic_id_candidate = _get_tactic_from_technique(technique_id_candidate)
                if tactic_id_candidate and tactic_id_candidate != "TA0000":
                    tactic_id = tactic_id_candidate
                    tactic_name = _get_tactic_name(tactic_id)
        
        # 设置 threat 信息（如果找到了标签，使用标签；否则使用默认值）
        tactic_obj = threat_obj.get("tactic")
        if not isinstance(tactic_obj, dict):
            tactic_obj = {}
            threat_obj["tactic"] = tactic_obj
        
        if tactic_id:
            tactic_obj["id"] = tactic_id
            tactic_obj["name"] = tactic_name
        else:
            tactic_obj.setdefault("id", "TA0000")
            tactic_obj.setdefault("name", "Unknown")
        
        technique_obj = threat_obj.get("technique")
        if not isinstance(technique_obj, dict):
            technique_obj = {}
            threat_obj["technique"] = technique_obj
        
        if technique_id:
            technique_obj["id"] = technique_id
            # 如果有 technique ID，尝试获取名称（可以从映射表或保持默认）
            technique_obj.setdefault("name", "Security Analytics Detection")
        else:
            technique_obj.setdefault("id", "T0000")
            technique_obj.setdefault("name", "Unknown")

    # Telemetry dataset-specific IDs
    dataset0 = event_obj.get("dataset") if isinstance(event_obj.get("dataset"), str) else ""
    if kind == "event" and dataset0 == "hostlog.auth":
        session_obj = doc.get("session")
        if not isinstance(session_obj, dict):
            session_obj = {}
            doc["session"] = session_obj
        if not isinstance(session_obj.get("id"), str) or not session_obj.get("id").strip():
            user_obj = doc.get("user") if isinstance(doc.get("user"), dict) else {}
            source_obj = doc.get("source") if isinstance(doc.get("source"), dict) else {}
            user_name = user_obj.get("name") if isinstance(user_obj.get("name"), str) else None
            source_ip = source_obj.get("ip") if isinstance(source_obj.get("ip"), str) else None
            ts = parse_datetime(doc.get("@timestamp"))
            host_id0 = host_obj.get("id") if isinstance(host_obj.get("id"), str) else None
            if user_name and source_ip and host_id0 and ts is not None:
                bucket = int(ts.timestamp()) // 300
                raw = f"{host_id0}:{user_name}:{source_ip}:{bucket}"
                session_obj["id"] = f"sess-{_sha1_hex(raw)[:16]}"

    if kind == "event" and dataset0 == "hostlog.process":
        process_obj = doc.get("process")
        if isinstance(process_obj, dict):
            if not isinstance(process_obj.get("entity_id"), str) or not process_obj.get("entity_id").strip():
                pid = process_obj.get("pid")
                exe = process_obj.get("executable")
                start_ts = to_rfc3339(process_obj.get("start")) or to_rfc3339(process_obj.get("start_time"))
                if not start_ts:
                    start_ts = doc.get("@timestamp") if isinstance(doc.get("@timestamp"), str) else None
                host_id0 = host_obj.get("id") if isinstance(host_obj.get("id"), str) else None
                if host_id0 and isinstance(pid, (int, float)) and isinstance(exe, str) and exe and start_ts:
                    raw = f"{host_id0}:{int(pid)}:{start_ts}:{exe}"
                    process_obj["entity_id"] = f"p-{_sha1_hex(raw)[:16]}"

    return doc


def _normalize_three_timestamps(doc: dict[str, Any], *, ingested_now: str) -> dict[str, Any] | None:
    """
    Enforce docs/51-ECS字段规范.md 三时间字段：
    - @timestamp: 主时间轴（必须可推导；否则丢弃）
    - event.created: 观察时间（缺失则回填为 @timestamp）
    - event.ingested: 中心侧入库时间（总是覆盖为 now）
    """
    ts = _extract_timestamp(doc)
    if not ts:
        return None

    doc["@timestamp"] = ts

    # Normalize legacy flattened keys into the nested event object.
    legacy_created = _to_rfc3339(doc.pop("event.created", None))
    doc.pop("event.ingested", None)

    event_obj = doc.get("event")
    if not isinstance(event_obj, dict):
        event_obj = {}
        doc["event"] = event_obj

    created = _to_rfc3339(event_obj.get("created")) or legacy_created or ts
    event_obj["created"] = created

    # Decision: center always overwrites event.ingested.
    event_obj["ingested"] = ingested_now

    return doc


def route_to_index(item: dict[str, Any]) -> str:
    """根据event.kind和event.dataset路由到对应索引"""
    event = item.get("event", {})
    kind = event.get("kind") or item.get("event.kind")
    dataset = event.get("dataset") or item.get("event.dataset", "")

    # Index rollovers should follow UTC day boundaries.
    from datetime import datetime, timezone

    today = datetime.now(timezone.utc)

    if kind == "event":
        # Telemetry -> ecs-events-*
        return get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)
    elif kind == "alert":
        if dataset == "finding.canonical":
            # Canonical Findings -> canonical-findings-*
            return get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)
        else:
            # Raw Findings -> raw-findings-*
            return get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)

    # 默认路由到ecs-events
    return get_index_name(INDEX_PATTERNS["ECS_EVENTS"], today)


def _get_event_id(event: dict[str, Any]) -> str | None:
    """从事件中提取event.id"""
    event_obj = event.get("event")
    if isinstance(event_obj, dict):
        value = event_obj.get("id")
        if isinstance(value, str) and value:
            return value
    value = event.get("event.id")
    if isinstance(value, str) and value:
        return value
    return None


def _is_duplicate(index_name: str, event_id: str) -> bool:
    """检查事件是否已存在（去重）"""
    if not event_id:
        return False
    existing = get_document(index_name, event_id)
    return existing is not None


def store_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """
    存储数据到OpenSearch（自动路由到对应索引，并去重）
    
    去重逻辑：在入库时检查 event.id 是否已存在，如果存在则丢弃，不存在则存储
    
    Returns:
        {
            "total": int,      # 总事件数
            "success": int,     # 成功存储数（去重后）
            "failed": int,      # 失败数
            "duplicated": int,  # 重复数（被丢弃的）
            "details": {        # 每个索引的详细统计
                "index_name": {
                    "success": int,
                    "failed": int,
                    "duplicated": int
                }
            }
        }
    """
    if len(events) == 0:
        return {"total": 0, "success": 0, "failed": 0, "duplicated": 0, "dropped": 0, "details": {}}

    # 按索引分组，并去重
    index_groups: dict[str, list[dict[str, Any]]] = {}
    total_duplicated = 0
    total_dropped = 0
    ingested_now = utc_now_rfc3339()

    for event in events:
        if not isinstance(event, dict):
            total_dropped += 1
            continue

        _dotted_to_nested(event)
        if _normalize_three_timestamps(event, ingested_now=ingested_now) is None:
            total_dropped += 1
            continue
        if _ensure_required_fields(event) is None:
            total_dropped += 1
            continue

        # Enforce docs/51-ECS字段规范.md: event.id is the idempotency key.
        event_id = _get_event_id(event)
        if not event_id:
            total_dropped += 1
            continue

        # Enforce docs/51-ECS字段规范.md: only "event" (Telemetry) and "alert" (Findings) are valid.
        event_obj = event.get("event", {})
        kind = (
            (event_obj.get("kind") if isinstance(event_obj, dict) else None)
            or event.get("event.kind")
        )
        if kind not in ("event", "alert"):
            total_dropped += 1
            continue

        index_name = route_to_index(event)

        # 去重检查：如果event.id已存在，则跳过
        if event_id and _is_duplicate(index_name, event_id):
            total_duplicated += 1
            continue

        if index_name not in index_groups:
            index_groups[index_name] = []
        index_groups[index_name].append({
            "id": event_id,
            "document": event,
        })

    # 批量写入每个索引
    details: dict[str, dict[str, int]] = {}
    total_success = 0
    total_failed = 0

    for index_name, documents in index_groups.items():
        try:
            result = bulk_index(index_name, documents)
            details[index_name] = {
                "success": result["success"],
                "failed": result.get("failed", 0),
                "duplicated": 0,  # 去重已在上面完成
            }
            total_success += result["success"]
            total_failed += result.get("failed", 0)
            # 优化：减少refresh频率，避免OOM
            # 只在批量写入大量数据后refresh一次，而不是每次写入都refresh
            # refresh_index(index_name)  # 注释掉，减少内存压力
        except Exception as error:
            print(f"存储到索引 {index_name} 失败: {error}")
            details[index_name] = {
                "success": 0,
                "failed": len(documents),
                "duplicated": 0,
            }
            total_failed += len(documents)

    return {
        "total": len(events),
        "success": total_success,
        "failed": total_failed,
        "duplicated": total_duplicated,
        "dropped": total_dropped,
        "details": details,
    }
