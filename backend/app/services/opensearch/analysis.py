# OpenSearch 数据分析模块
# 包含 Security Analytics 检测调用和告警融合去重

"""
OpenSearch 数据分析模块

包含 Security Analytics 检测调用和告警融合去重功能。
"""

import hashlib
import os
from typing import Any, Optional
from datetime import datetime, timedelta, timezone

from app.core.time import parse_datetime, to_rfc3339, utc_now_rfc3339

from .client import get_client, search, bulk_index, refresh_index
from .index import INDEX_PATTERNS, get_index_name

# ========== 常量定义 ==========

# 时间窗口（分钟），用于时间桶计算
TIME_WINDOW_MINUTES = 3  # 实验规模小，建议偏小（1-5分钟）

# Security Analytics API 路径
SA_DETECTORS_SEARCH_API = "/_plugins/_security_analytics/detectors/_search"
SA_DETECTOR_GET_API = "/_plugins/_security_analytics/detectors/{detector_id}"
SA_DETECTOR_UPDATE_API = "/_plugins/_security_analytics/detectors/{detector_id}"
SA_FINDINGS_SEARCH_API = "/_plugins/_security_analytics/findings/_search"
# 注意：某些版本 workflows/_search 不存在或被当成 id 路由，所以只用 monitors/_search
ALERTING_MONITORS_SEARCH_API = "/_plugins/_alerting/monitors/_search"  # 统一使用 monitors 搜索
ALERTING_WORKFLOW_EXECUTE_API = "/_plugins/_alerting/monitors/{workflow_id}/_execute"  # workflow ID 就是 monitor ID，用 monitor execute

# 缓存时间窗口（秒）：如果findings在5分钟内，直接使用，不触发新扫描
FINDINGS_CACHE_WINDOW_SECONDS = 300  # 5分钟

# 默认超时设置
DEFAULT_SCAN_TIMEOUT_SECONDS = 60  # 扫描超时时间（秒）
DEFAULT_POLL_INTERVAL_SECONDS = 2  # 轮询间隔（秒）


def fingerprint_id_from_key(fingerprint_key: str) -> str:
    """
    将用于分组/融合的“原始指纹 key”转换为 docs 约定的 custom.finding.fingerprint。

    docs/51-ECS字段规范.md 约定（简化表达）：
    fingerprint = sha1(technique_id + host + entity + time_bucket)

    当前实现中，generate_fingerprint() 返回的是可读的 key：
    {technique_id}|{host_id}|{entity_id}|{time_bucket}

    这里按文档语义对其做 sha1，再加上 fp- 前缀，得到可存储/可查询/可展示的 fingerprint。
    """
    digest = hashlib.sha1(fingerprint_key.encode("utf-8")).hexdigest()
    return f"fp-{digest}"


def generate_fingerprint(finding: dict[str, Any]) -> str:
    """
    生成告警指纹
    指纹 = technique_id + host + (process_entity_id | dst_ip/domain | file_hash) + time_bucket
    """
    technique_id = (
        finding.get("threat", {}).get("technique", {}).get("id")
        or finding.get("threat.technique.id")
        or "unknown"
    )
    host_id = finding.get("host", {}).get("id") or finding.get("host.id") or "unknown"

    # 实体标识符（优先级：process_entity_id > dst_ip/domain > file_hash）
    entity_id = "unknown"
    if finding.get("process", {}).get("entity_id") or finding.get("process.entity_id"):
        entity_id = finding.get("process", {}).get("entity_id") or finding.get("process.entity_id")
    elif finding.get("destination", {}).get("ip") or finding.get("destination.ip"):
        entity_id = finding.get("destination", {}).get("ip") or finding.get("destination.ip")
        if finding.get("destination", {}).get("domain") or finding.get("destination.domain"):
            entity_id += "|" + (
                finding.get("destination", {}).get("domain") or finding.get("destination.domain")
            )
    elif finding.get("file", {}).get("hash", {}).get("sha256") or finding.get("file.hash.sha256"):
        entity_id = (
            finding.get("file", {}).get("hash", {}).get("sha256")
            or finding.get("file.hash.sha256")
        )

    # 时间桶计算：time_bucket = floor(@timestamp / Δt)
    timestamp_value = finding.get("@timestamp") or finding.get("event", {}).get("created")
    dt = parse_datetime(timestamp_value)
    if dt is None:
        dt = datetime.now(timezone.utc)
    timestamp_ms = int(dt.timestamp() * 1000)
    
    time_bucket_ms = TIME_WINDOW_MINUTES * 60 * 1000  # 转换为毫秒
    time_bucket = timestamp_ms // time_bucket_ms

    return f"{technique_id}|{host_id}|{entity_id}|{time_bucket}"


def extract_provider(finding: dict[str, Any]) -> str:
    """从 Raw Finding 提取 provider（来源引擎）"""
    # 如果已经有 custom.finding.providers，取第一个
    custom = finding.get("custom", {})
    finding_custom = custom.get("finding", {})
    providers = finding_custom.get("providers")
    if isinstance(providers, list) and len(providers) > 0:
        return providers[0]

    dataset = finding.get("event", {}).get("dataset") or finding.get("event.dataset")
    if isinstance(dataset, str) and dataset.startswith("finding.raw."):
        provider = dataset.split("finding.raw.", 1)[1]
        if provider in {"falco", "suricata", "filebeat_sigma", "security_analytics"}:
            return provider

    # 根据规则来源推断
    rule_id = finding.get("rule", {}).get("id") or finding.get("rule.id")
    if rule_id:
        rule_id_lower = rule_id.lower()
        if "filebeat" in rule_id_lower or "sigma" in rule_id_lower:
            return "filebeat_sigma"
        if "falco" in rule_id_lower:
            return "falco"
        if "suricata" in rule_id_lower:
            return "suricata"
        if "opensearch" in rule_id_lower or "security_analytics" in rule_id_lower:
            return "security_analytics"

    return "unknown"


def merge_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """合并多个 Raw Findings 为一条 Canonical Finding"""
    if len(findings) == 0:
        raise ValueError("无法合并空数组")

    # 使用第一个 finding 作为基础
    import copy

    base = copy.deepcopy(findings[0])

    # 合并 providers（优先信任 custom.finding.providers；缺失时再推断）
    providers = set()
    for f in findings:
        f_custom = f.get("custom", {})
        f_finding = f_custom.get("finding", {})
        f_providers = f_finding.get("providers")
        if isinstance(f_providers, list):
            providers.update(f_providers)
        provider = extract_provider(f)
        if provider != "unknown":
            providers.add(provider)

    # 合并 evidence.event_ids（只允许 Telemetry event.id；不要把 finding 自身的 event.id 混进来）
    event_ids = set()
    for f in findings:
        f_custom = f.get("custom", {})
        f_evidence = f_custom.get("evidence", {})
        f_event_ids = f_evidence.get("event_ids")
        if isinstance(f_event_ids, list):
            event_ids.update(f_event_ids)

    # 合并 severity（取最大值）
    max_severity = base.get("event", {}).get("severity") or base.get("event.severity") or 0
    for f in findings:
        severity = f.get("event", {}).get("severity") or f.get("event.severity") or 0
        if severity > max_severity:
            max_severity = severity

    # 构建 Canonical Finding
    if "custom" not in base:
        base["custom"] = {}
    if "finding" not in base["custom"]:
        base["custom"]["finding"] = {}

    base["custom"]["finding"]["stage"] = "canonical"
    base["custom"]["finding"]["providers"] = sorted(p for p in providers if isinstance(p, str) and p)

    if "evidence" not in base["custom"]:
        base["custom"]["evidence"] = {}
    base["custom"]["evidence"]["event_ids"] = sorted(e for e in event_ids if isinstance(e, str) and e)

    # 设置 severity
    if "event" in base:
        base["event"]["severity"] = max_severity
    else:
        base["event.severity"] = max_severity

    # 设置 dataset
    if "event" in base:
        base["event"]["dataset"] = "finding.canonical"
        base["event"]["kind"] = "alert"
    else:
        base["event.dataset"] = "finding.canonical"
        base["event.kind"] = "alert"

    # confidence 可按来源数量上调（来源越多，置信度越高）
    confidence = min(0.5 + (len(providers) * 0.15), 1.0)  # 基础 0.5，每个来源 +0.15，最高 1.0
    base["custom"]["confidence"] = confidence

    # 生成新的 event.id（基于指纹）
    fingerprint = generate_fingerprint(base)
    base["custom"]["finding"]["fingerprint"] = fingerprint_id_from_key(fingerprint)
    hash_value = hashlib.sha256(fingerprint.encode()).hexdigest()[:16]
    if "event" not in base:
        base["event"] = {}
    base["event"]["id"] = f"canonical-{hash_value}"

    return base


def deduplicate_findings() -> dict[str, Any]:
    """
    告警融合去重（Raw Findings → Canonical Findings）
    根据文档：在时间窗 Δt 内，将满足相同指纹的 Raw Finding 合并为一条 Canonical Finding
    """
    client = get_client()
    today = datetime.now(timezone.utc)
    raw_index_name = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
    canonical_index_name = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)

    try:
        canonical_ingested_now = utc_now_rfc3339()

        # 查询所有 Raw Findings
        raw_findings = search(
            raw_index_name,
            {"match_all": {}},
            10000,  # 可根据实际情况调整
        )

        if len(raw_findings) == 0:
            return {"total": 0, "merged": 0, "canonical": 0, "errors": 0}

        # 按指纹分组
        fingerprint_groups: dict[str, list[dict[str, Any]]] = {}
        for finding in raw_findings:
            fingerprint = generate_fingerprint(finding)
            if fingerprint not in fingerprint_groups:
                fingerprint_groups[fingerprint] = []
            fingerprint_groups[fingerprint].append(finding)

        # 合并每个分组
        canonical_findings: list[dict[str, Any]] = []
        merged_count = 0

        for fingerprint, findings in fingerprint_groups.items():
            if len(findings) > 1:
                # 多个 findings 需要合并
                merged = merge_findings(findings)
                canonical_findings.append(merged)
                merged_count += len(findings)
            else:
                # 单个 finding，直接转为 canonical（更新字段）
                import copy

                single = copy.deepcopy(findings[0])
                if "custom" not in single:
                    single["custom"] = {}
                if "finding" not in single["custom"]:
                    single["custom"]["finding"] = {}
                single["custom"]["finding"]["stage"] = "canonical"
                if "providers" not in single["custom"]["finding"]:
                    single["custom"]["finding"]["providers"] = [extract_provider(single)]
                single["custom"]["finding"]["fingerprint"] = fingerprint_id_from_key(fingerprint)

                if "event" in single:
                    single["event"]["dataset"] = "finding.canonical"
                    single["event"]["kind"] = "alert"
                else:
                    single["event.dataset"] = "finding.canonical"
                    single["event.kind"] = "alert"

                canonical_findings.append(single)

        # Canonical Finding 是中心侧生成的“新文档”，入库时间应为生成时刻。
        # 同时确保三时间字段存在：缺少主时间轴（@timestamp 或可推导字段）则丢弃该 canonical。
        normalized_canonicals: list[dict[str, Any]] = []
        for f in canonical_findings:
            ts = f.get("@timestamp")
            if not ts:
                event_obj = f.get("event") if isinstance(f.get("event"), dict) else {}
                ts = event_obj.get("created") or f.get("event.created")
            if not ts:
                continue

            f["@timestamp"] = ts

            event_obj = f.get("event")
            if not isinstance(event_obj, dict):
                event_obj = {}
                f["event"] = event_obj

            if not event_obj.get("created"):
                event_obj["created"] = ts

            # Decision: canonical 的入库时间为生成时刻（中心侧覆盖）。
            event_obj["ingested"] = canonical_ingested_now

            normalized_canonicals.append(f)

        # 批量写入 Canonical Findings
        if len(normalized_canonicals) > 0:
            documents = [
                {
                    "id": f.get("event", {}).get("id") or f.get("event.id"),
                    "document": f,
                }
                for f in normalized_canonicals
            ]

            result = bulk_index(canonical_index_name, documents)
            # 刷新索引，使新写入的 Canonical Findings 立即可搜索
            if result.get("success", 0) > 0:
                refresh_index(canonical_index_name)

            return {
                "total": len(raw_findings),
                "merged": merged_count,
                "canonical": len(normalized_canonicals),
                "errors": result.get("failed", 0),
            }

        return {"total": len(raw_findings), "merged": merged_count, "canonical": 0, "errors": 0}
    except Exception as error:
        print(f"告警融合去重失败: {error}")
        raise


def _convert_security_analytics_finding_to_ecs(finding: dict[str, Any]) -> dict[str, Any]:
    """
    将 Security Analytics 的 finding 转换为 ECS 格式的 Finding
    
    人话解释：
    - Security Analytics 返回的 finding 格式和我们的 ECS 格式不一样
    - 这个函数就是把它的格式转换成我们系统能用的格式
    - 就像把"外国话"翻译成"中国话"
    """
    # 提取基本信息
    finding_id = finding.get("id") or f"sa-finding-{int(datetime.now(timezone.utc).timestamp())}"
    timestamp = to_rfc3339(finding.get("timestamp")) or utc_now_rfc3339()
    
    # 提取检测信息
    detector = finding.get('detector', {})
    detector_id = detector.get('id', 'unknown')
    detector_name = detector.get('name', 'Security Analytics Detector')
    
    # 提取规则信息
    queries = finding.get('queries', [])
    rule_info = {}
    if queries:
        # 取第一个查询作为规则信息
        first_query = queries[0]
        rule_info = {
            "id": f"sa-rule-{detector_id}",
            "name": first_query.get('name', 'Security Analytics Rule'),
            "version": "1.0",
        }
    
    # 提取威胁信息（如果有）
    threat_info = {}
    tags = finding.get('tags', [])
    for tag in tags:
        # 尝试从标签中提取 ATT&CK 信息
        if isinstance(tag, str) and tag.startswith('attack.'):
            parts = tag.split('.')
            if len(parts) >= 3:
                tactic_id = parts[1] if parts[1].startswith('TA') else None
                technique_id = parts[2] if parts[2].startswith('T') else None
                if technique_id:
                    threat_info = {
                        "tactic": {
                            "id": tactic_id or "TA0000",
                            "name": "Unknown"
                        },
                        "technique": {
                            "id": technique_id,
                            "name": "Security Analytics Detection"
                        }
                    }
                    break
    
    # 如果没有从标签提取到，使用默认值
    if not threat_info:
        threat_info = {
            "tactic": {
                "id": "TA0000",
                "name": "Unknown"
            },
            "technique": {
                "id": "T0000",
                "name": "Security Analytics Detection"
            }
        }
    
    # 提取文档信息（原始事件）
    document_list = finding.get('document_list', [])
    related_events = []
    host_info = {}
    
    if document_list:
        # 取第一个文档作为主要事件
        first_doc = document_list[0]
        if isinstance(first_doc, dict):
            # 提取主机信息
            if 'host' in first_doc:
                host_info = first_doc['host']
            elif 'host.id' in first_doc:
                host_info = {
                    "id": first_doc.get('host.id'),
                    "name": first_doc.get('host.name', 'unknown')
                }
            
            # 收集相关事件 ID
            if 'event' in first_doc and 'id' in first_doc['event']:
                related_events.append(first_doc['event']['id'])
    
    # 构建 ECS 格式的 Finding
    ecs_finding = {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp,
        "event": {
            "id": finding_id,
            "kind": "alert",
            "created": timestamp,
            "ingested": timestamp,
            "category": ["intrusion_detection"],
            "type": ["alert"],
            "action": "security_analytics_detection",
            "dataset": "finding.raw.security_analytics",
            "severity": finding.get('severity', 50),  # Security Analytics 的严重程度
        },
        "rule": rule_info if rule_info else {
            "id": f"sa-rule-{detector_id}",
            "name": detector_name,
            "version": "1.0",
        },
        "threat": threat_info,
        "custom": {
            "finding": {
                "stage": "raw",
                "providers": ["security_analytics"],  # 标记来源（docs/51-ECS字段规范.md）
            },
            "confidence": finding.get('confidence', 0.7),
        },
        "host": host_info if host_info else {
            "id": "unknown",
            "name": "unknown"
        },
        "message": finding.get('description', f"Security Analytics detection from {detector_name}"),
    }
    
    # 如果有相关事件，添加到 evidence
    if related_events:
        ecs_finding["custom"]["evidence"] = {
            "event_ids": related_events
        }

    # 为 raw finding 也生成 fingerprint（便于排障与融合去重可观测）
    try:
        fp_key = generate_fingerprint(ecs_finding)
        ecs_finding["custom"]["finding"]["fingerprint"] = fingerprint_id_from_key(fp_key)
    except Exception:
        pass
    
    return ecs_finding


def _get_workflow_id_for_detector(client, detector_id: str) -> Optional[str]:
    """
    根据detector_id获取对应的workflow_id
    
    策略（按优先级）：
    1. 先检查detector详情里是否有monitor_id（最直接）
    2. 通过monitors/_search查找workflow（兼容keyword/text字段）
    
    注意：某些detector可能没有workflow，这是正常的。如果没有workflow，
    可以使用schedule方式触发扫描（同样有效）。
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID
    
    返回：
    - workflow_id: 如果找到则返回workflow ID（即monitor ID），否则返回None
    """
    # 方法1：先检查detector详情里是否有monitor_id（最直接的方式）
    try:
        print(f"[DEBUG] 检查detector详情中是否有monitor_id...")
        detector = _get_detector_details(client, detector_id)
        if detector:
            # 检查多种可能的字段名
            monitor_id = (
                detector.get('monitor_id') or 
                detector.get('monitorId') or 
                (detector.get('monitor_ids', [None])[0] if isinstance(detector.get('monitor_ids'), list) else None) or
                detector.get('workflow_id') or 
                detector.get('workflowId')
            )
            if monitor_id:
                print(f"[DEBUG] 在detector详情中找到monitor_id: {monitor_id}")
                return monitor_id
            else:
                print(f"[DEBUG] detector详情中没有monitor_id字段")
                # 打印detector的所有keys以便调试
                print(f"[DEBUG] detector的keys: {list(detector.keys())}")
    except Exception as e:
        print(f"[DEBUG] 检查detector详情失败: {e}")
    
    # 方法2：通过monitors/_search查找workflow（兼容keyword/text字段）
    try:
        print(f"[DEBUG] 通过monitors搜索API查找workflow...")
        
        # 先查询所有monitors，看看实际返回什么
        print(f"[DEBUG] 先查询所有monitors（不限制条件）...")
        all_monitors_resp = client.transport.perform_request(
            'POST',
            ALERTING_MONITORS_SEARCH_API,
            body={"query": {"match_all": {}}, "size": 50}
        )
        
        # 使用统一的提取函数
        all_hits = all_monitors_resp.get('hits', {}).get('hits', [])
        
        print(f"[DEBUG] 找到 {len(all_hits)} 个monitors")
        print(f"[DEBUG] 响应顶层keys: {list(all_monitors_resp.keys())}")
        if all_hits:
            # 打印所有monitor的关键字段以便调试
            for i, hit in enumerate(all_hits[:3]):  # 只打印前3个
                source = hit.get('_source', {}) if '_source' in hit else hit
                hit_id = hit.get('_id') if '_id' in hit else hit.get('id')
                print(f"[DEBUG] Monitor {i+1}: id={hit_id}, name={source.get('name')}, type={source.get('type')}, monitor_type={source.get('monitor_type')}, owner={source.get('owner')}")
        
        # 查询workflow：兼容keyword/text字段，使用should+minimum_should_match
        # 注意：workflow的type=workflow，monitor_type可能是None或composite
        workflow_query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"type.keyword": "workflow"}},  # 优先用keyword
                                    {"match": {"type": "workflow"}},  # fallback到match
                                    {"term": {"monitor_type.keyword": "composite"}},
                                    {"match": {"monitor_type": "composite"}}
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {"term": {"owner.keyword": "security_analytics"}},
                                    {"match": {"owner": "security_analytics"}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            },
            "size": 50
        }
        
        # 先尝试严格查询
        workflow_resp = client.transport.perform_request(
            'POST',
            ALERTING_MONITORS_SEARCH_API,
            body=workflow_query
        )
        
        hits = workflow_resp.get('hits', {}).get('hits', [])
        
        # 如果严格查询没结果，尝试更宽松的查询：只匹配type=workflow和owner=security_analytics
        if not hits:
            print(f"[DEBUG] 严格查询无结果，尝试更宽松的查询（只匹配type=workflow和owner）...")
            # 尝试多种查询方式：term/match，keyword/非keyword
            relaxed_query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "bool": {
                                    "should": [
                                        {"term": {"type": "workflow"}},  # 先尝试非keyword
                                        {"term": {"type.keyword": "workflow"}},  # 再尝试keyword
                                        {"match": {"type": "workflow"}}  # 最后用match
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {"term": {"owner": "security_analytics"}},  # 先尝试非keyword
                                        {"term": {"owner.keyword": "security_analytics"}},  # 再尝试keyword
                                        {"match": {"owner": "security_analytics"}}  # 最后用match
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                },
                "size": 50
            }
            workflow_resp = client.transport.perform_request(
                'POST',
                ALERTING_MONITORS_SEARCH_API,
                body=relaxed_query
            )
            hits = workflow_resp.get('hits', {}).get('hits', [])
            
            # 如果还是没结果，直接从所有monitors中筛选（fallback）
            if not hits:
                print(f"[DEBUG] 宽松查询也无结果，直接从所有monitors中筛选workflow...")
                for hit in all_hits:
                    source = hit.get('_source', {}) if '_source' in hit else hit
                    hit_type = source.get('type')
                    hit_owner = source.get('owner')
                    if hit_type == 'workflow' and hit_owner == 'security_analytics':
                        print(f"[DEBUG] 从所有monitors中找到workflow: {hit.get('_id')}")
                        hits = [hit]
                        break
        
        print(f"[DEBUG] monitors搜索API（workflow查询）返回了 {len(hits)} 个结果")
        if hits:
            for i, hit in enumerate(hits):
                source = hit.get('_source', {}) if '_source' in hit else hit
                hit_id = hit.get('_id') if '_id' in hit else hit.get('id')
                print(f"[DEBUG] Workflow {i+1}: id={hit_id}, name={source.get('name')}, type={source.get('type')}, monitor_type={source.get('monitor_type')}, owner={source.get('owner')}")
                # 打印inputs结构（可能包含detector关联信息）
                inputs = source.get('inputs', [])
                if inputs:
                    print(f"[DEBUG]   inputs类型: {type(inputs)}")
                    if isinstance(inputs, list) and len(inputs) > 0:
                        print(f"[DEBUG]   第一个inputs的keys: {list(inputs[0].keys()) if isinstance(inputs[0], dict) else 'not dict'}")
        
        # 简单策略：返回第一个匹配的workflow（通常只有一个）
        if hits:
            return hits[0].get('_id')
    except Exception as e:
        error_msg = str(e)
        error_type = type(e).__name__
        print(f"[DEBUG] monitors搜索API失败: {error_type}: {error_msg}")
    
    print(f"[DEBUG] 未找到匹配detector {detector_id} 的workflow")
    return None


def _get_latest_findings_timestamp(client, detector_id: Optional[str] = None) -> tuple[int, int]:
    """
    获取最新findings的时间戳和数量（用于轮询确认）
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID（可选）
    
    返回：
    - (timestamp_ms, count): 最新finding的时间戳（毫秒）和总数
      如果查询失败或没有findings，返回 (0, 0)
    """
    try:
        params = {
            'size': 1,  # 只要最新的一个
            'sortString': 'timestamp',
            'sortOrder': 'desc'
        }
        if detector_id:
            params['detector_id'] = detector_id
        
        findings_resp = client.transport.perform_request(
            'GET',
            SA_FINDINGS_SEARCH_API,
            params=params
        )
        
        # 提取findings
        findings = findings_resp.get('findings', [])
        total_findings = findings_resp.get('total_findings', len(findings))
        
        if not findings:
            return (0, total_findings)
        
        # 获取最新finding的时间戳
        latest_finding = findings[0]
        timestamp_value = latest_finding.get('timestamp') or latest_finding.get('@timestamp')
        
        dt = parse_datetime(timestamp_value)
        timestamp_ms = int(dt.timestamp() * 1000) if dt is not None else 0
        
        return (timestamp_ms, total_findings)
    except Exception as e:
        print(f"[WARNING] 查询findings时间戳失败: {e}")
        return (0, 0)


def _get_latest_findings_count(client, detector_id: str) -> int:
    """
    使用Security Analytics的findings API获取findings数量
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID
    
    返回：
    - findings数量（如果查询失败则返回0）
    """
    _, count = _get_latest_findings_timestamp(client, detector_id)
    return count


# ========== 辅助函数：查询detector相关 ==========

def _get_detector_id(client) -> Optional[str]:
    """获取第一个detector的ID"""
    try:
        detector_resp = client.transport.perform_request(
            'POST',
            SA_DETECTORS_SEARCH_API,
            body={"query": {"match_all": {}}, "size": 1}
        )
        detector_hits = detector_resp.get('hits', {}).get('hits', [])
        return detector_hits[0].get('_id') if detector_hits else None
    except Exception:
        return None


def _get_detector_details(client, detector_id: str) -> Optional[dict]:
    """获取detector详情"""
    try:
        detector_resp = client.transport.perform_request(
            'GET',
            SA_DETECTOR_GET_API.format(detector_id=detector_id)
        )
        return detector_resp.get('detector', {})
    except Exception:
        return None


def _should_trigger_scan(trigger_scan: bool, baseline_count: int) -> bool:
    """
    判断是否需要触发新扫描
    
    注意：这个函数已废弃，现在使用更详细的逻辑（检查findings年龄）
    保留此函数是为了向后兼容
    """
    # 旧逻辑：只有当没有findings时才触发
    # 新逻辑在 run_security_analytics 中实现（检查findings年龄）
    return trigger_scan and baseline_count == 0


# ========== 辅助函数：触发扫描相关 ==========

def _is_timestamp_string(value) -> bool:
    """判断一个值是否是ISO格式的时间戳字符串"""
    if not isinstance(value, str):
        return False
    # 检查是否是ISO格式的时间戳（如 "2026-01-14T04:44:38.487Z"）
    import re
    iso_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?$'
    return bool(re.match(iso_pattern, value))


def _clean_detector_for_update(detector: dict) -> dict:
    """
    清理detector对象，移除可能导致更新错误的字段
    
    移除的字段：
    - 时间戳字段（last_update_time, created_at, updated_at等）
    - OpenSearch元数据字段（_version, _seq_no, _primary_term等）
    - 任何ISO格式的时间戳字符串值
    - 保留核心字段：name, type, detector_type, schedule, enabled, inputs等
    """
    # 需要移除的字段列表（时间戳和元数据字段）
    fields_to_remove = [
        'last_update_time',
        'created_at',
        'updated_at',
        '@timestamp',
        '_version',
        '_seq_no',
        '_primary_term',
        'monitor_id',  # 可能由系统管理
        'detector_id',  # 由URL参数提供，不应在body中
    ]
    
    cleaned = detector.copy()
    
    # 移除已知的时间戳和元数据字段
    for field in fields_to_remove:
        cleaned.pop(field, None)
    
    # 递归清理：移除任何值是ISO时间戳字符串的字段
    def clean_dict_recursive(obj):
        if isinstance(obj, dict):
            cleaned_obj = {}
            for key, value in obj.items():
                # 跳过时间戳字段名
                if any(time_word in key.lower() for time_word in ['time', 'date', 'timestamp', 'created', 'updated']):
                    continue
                # 跳过ISO时间戳字符串值
                if _is_timestamp_string(value):
                    continue
                # 递归清理嵌套对象
                cleaned_obj[key] = clean_dict_recursive(value)
            return cleaned_obj
        elif isinstance(obj, list):
            return [clean_dict_recursive(item) for item in obj]
        else:
            return obj
    
    cleaned = clean_dict_recursive(cleaned)
    
    return cleaned


def _execute_workflow_manually(client, workflow_id: str) -> bool:
    """
    手动执行workflow（立即触发扫描，不等schedule）
    
    注意：workflow本质上就是composite monitor，所以使用monitor execute API
    这是推荐的触发方式：直接调用monitor的_execute API，比临时改schedule更干净
    
    参数：
    - client: OpenSearch客户端
    - workflow_id: Workflow ID（即monitor ID）
    
    返回：
    - True: 执行成功
    - False: 执行失败
    """
    # 先尝试GET monitor配置，检查是否有读取权限（可选检查，不影响执行）
    # 注意：即使GET失败，execute API可能仍然可以工作，因为execute可能不需要读取完整配置
    try:
        print(f"[DEBUG] 先检查是否有读取monitor配置的权限...")
        monitor_get_path = f"/_plugins/_alerting/monitors/{workflow_id}"
        monitor_config = client.transport.perform_request('GET', monitor_get_path)
        print(f"[DEBUG] GET monitor配置成功，有读取权限")
    except Exception as get_error:
        error_msg = str(get_error)
        error_type = type(get_error).__name__
        print(f"[WARNING] GET monitor配置失败: {error_type}: {error_msg}")
        # 注意：即使GET失败，我们仍然尝试执行workflow，因为execute API可能不需要读取完整配置
        # 某些OpenSearch版本中，execute API的权限检查可能独立于GET API
        if '403' in error_msg or 'forbidden' in error_msg.lower():
            print(f"[WARNING] GET权限不足，但继续尝试执行workflow（execute API可能有独立权限）")
        elif '500' in error_msg and ('indices:data/read/get' in error_msg or 'alerting_exception' in error_msg):
            print(f"[WARNING] GET时出现权限相关错误，但继续尝试执行workflow")
        # 不返回False，继续尝试execute
    
    # 尝试执行workflow
    try:
        print(f"[INFO] 手动执行workflow (monitor_id: {workflow_id})...")
        api_path = ALERTING_WORKFLOW_EXECUTE_API.format(workflow_id=workflow_id)
        print(f"[DEBUG] 调用API: POST {api_path}")
        execute_resp = client.transport.perform_request(
            'POST',
            api_path,
            body={}
        )
        
        # 检查响应是否成功
        # execute API通常返回执行结果，成功时可能有workflow_run_id、monitor_run_id等字段
        if execute_resp:
            print(f"[INFO] Workflow执行请求已提交，响应: {execute_resp}")
            # 检查响应中是否有执行ID（表示成功）
            if 'workflow_run_id' in execute_resp or 'monitor_run_id' in execute_resp or 'run_id' in execute_resp:
                print(f"[INFO] 执行ID: {execute_resp.get('workflow_run_id') or execute_resp.get('monitor_run_id') or execute_resp.get('run_id')}")
            return True
        else:
            print(f"[WARNING] Workflow执行请求返回空响应")
            return False
    except Exception as e:
        error_msg = str(e)
        error_type = type(e).__name__
        print(f"[WARNING] 手动执行workflow失败: {error_type}: {error_msg}")
        
        # 检查是否是权限问题
        if '500' in error_msg and ('alerting_exception' in error_msg or 'indices:data/read' in error_msg):
            print(f"[ERROR] 可能是权限问题：workflow执行时需要读取系统索引，但当前用户可能缺少权限")
            print(f"[ERROR] 需要权限：")
            print(f"[ERROR]   1. 对alerting系统索引的read/get权限（.opensearch-alerting-config等）")
            print(f"[ERROR]   2. 对业务索引的查询权限（ecs-events-*等）")
            print(f"[ERROR]   3. alerting插件的execute权限")
            print(f"[ERROR] 建议：将用户映射到alerting_full_access角色，或添加最小权限")
        
        import traceback
        print(f"[DEBUG] 错误详情: {traceback.format_exc()}")
        return False


def _enable_detector_if_needed(client, detector_id: str, detector: dict) -> None:
    """确保detector已启用"""
    if detector.get('enabled', False):
        return
    
    print(f"[INFO] 启用detector: {detector_id}")
    try:
        client.transport.perform_request(
            'PUT',
            SA_DETECTOR_UPDATE_API.format(detector_id=detector_id),
            body={**detector, "enabled": True}
        )
    except Exception as enable_error:
        print(f"[WARNING] 启用detector失败: {enable_error}")


def _temporarily_shorten_schedule(client, detector_id: str, detector: dict) -> tuple[dict, bool]:
    """
    临时缩短schedule以触发扫描
    
    返回: (original_schedule, was_shortened)
    """
    schedule = detector.get('schedule', {})
    original_schedule = schedule.copy()
    original_interval = schedule.get('period', {}).get('interval', 24)
    original_unit = schedule.get('period', {}).get('unit', 'HOURS')
    
    # 如果schedule间隔较长（>1小时），临时缩短为1分钟
    if original_unit == 'HOURS' and original_interval >= 1:
        print(f"[INFO] 临时缩短detector schedule以触发扫描...")
        
        temp_schedule = {"period": {"interval": 1, "unit": "MINUTES"}}
        
        try:
            cleaned_detector = _clean_detector_for_update(detector)
            cleaned_detector['schedule'] = temp_schedule
            cleaned_detector['enabled'] = True
            client.transport.perform_request(
                'PUT',
                SA_DETECTOR_UPDATE_API.format(detector_id=detector_id),
                body=cleaned_detector
            )
            print(f"[INFO] Schedule已临时设置为1分钟")
            return original_schedule, True
        except Exception as e:
            print(f"[WARNING] 设置临时schedule失败: {e}")
            return original_schedule, False
    
    # 如果schedule已经是分钟级别，通过临时禁用再启用来强制触发
    if original_unit == 'MINUTES':
        print(f"[INFO] Schedule已较短，通过禁用再启用来强制触发扫描...")
        try:
            cleaned_detector = _clean_detector_for_update(detector)
            
            # 临时禁用
            cleaned_detector_disabled = cleaned_detector.copy()
            cleaned_detector_disabled['enabled'] = False
            client.transport.perform_request(
                'PUT',
                SA_DETECTOR_UPDATE_API.format(detector_id=detector_id),
                body=cleaned_detector_disabled
            )
            import time
            time.sleep(1)  # 等待1秒确保禁用生效
            
            # 重新启用（这会触发一次扫描）
            cleaned_detector_enabled = cleaned_detector.copy()
            cleaned_detector_enabled['enabled'] = True
            client.transport.perform_request(
                'PUT',
                SA_DETECTOR_UPDATE_API.format(detector_id=detector_id),
                body=cleaned_detector_enabled
            )
            print(f"[INFO] Detector已重新启用，应触发扫描")
            return original_schedule, True
        except Exception as e:
            print(f"[WARNING] 强制触发扫描失败: {e}")
            return original_schedule, False
    
    return original_schedule, False


def _restore_schedule(client, detector_id: str, original_schedule: dict) -> None:
    """恢复原始schedule"""
    try:
        print(f"[INFO] 准备恢复schedule...")
        # 重新获取detector最新状态（避免覆盖其他修改）
        latest_resp = client.transport.perform_request(
            'POST',
            SA_DETECTORS_SEARCH_API,
            body={"query": {"term": {"_id": detector_id}}, "size": 1}
        )
        latest_hits = latest_resp.get('hits', {}).get('hits', [])
        
        if not latest_hits:
            print(f"[WARNING] 无法获取detector最新状态，schedule可能未恢复")
            return
        
        latest_detector = latest_hits[0].get('_source', {})
        original_interval = original_schedule.get('period', {}).get('interval', 24)
        original_unit = original_schedule.get('period', {}).get('unit', 'HOURS')
        
        # 恢复原始schedule
        client.transport.perform_request(
            'PUT',
            SA_DETECTOR_UPDATE_API.format(detector_id=detector_id),
            body={**latest_detector, "schedule": original_schedule, "enabled": True}
        )
        print(f"[INFO] Schedule已恢复为{original_interval} {original_unit}")
        
    except Exception as restore_error:
        print(f"[ERROR] 恢复schedule失败: {restore_error}")
        print(f"[WARNING] Detector schedule可能仍为1分钟，需要手动检查")


def _poll_for_scan_completion(
    client, 
    detector_id: str, 
    baseline_timestamp_ms: int,
    baseline_count: int, 
    max_wait_seconds: int
) -> tuple[bool, int]:
    """
    轮询确认扫描完成（通过时间戳判断，更准确）
    
    参数：
    - baseline_timestamp_ms: 基准时间戳（毫秒），新findings的时间戳应该大于此值
    - baseline_count: 基准数量，用于fallback判断
    
    返回: (scan_completed, scan_wait_ms)
    """
    import time
    
    start_time = time.time()
    print(f"[INFO] 开始轮询确认扫描完成（最多等待{max_wait_seconds}秒）...")
    
    while (time.time() - start_time) < max_wait_seconds:
        time.sleep(DEFAULT_POLL_INTERVAL_SECONDS)
        
        # 优先使用时间戳判断（更准确）
        current_timestamp_ms, current_count = _get_latest_findings_timestamp(client, detector_id)
        
        # 如果有新时间戳且大于基准时间戳，说明有新findings
        if baseline_timestamp_ms > 0 and current_timestamp_ms > baseline_timestamp_ms:
            scan_wait_ms = int((time.time() - start_time) * 1000)
            print(f"[INFO] 扫描完成！发现新findings（时间戳: {baseline_timestamp_ms} -> {current_timestamp_ms}）")
            return True, scan_wait_ms
        
        # Fallback: 如果时间戳判断不可用，使用数量判断
        if baseline_timestamp_ms == 0 and current_count > baseline_count:
            scan_wait_ms = int((time.time() - start_time) * 1000)
            print(f"[INFO] 扫描完成！Findings更新: {baseline_count} -> {current_count}")
            return True, scan_wait_ms
        
        elapsed = int(time.time() - start_time)
        if elapsed % 10 == 0:
            print(f"[INFO] 等待扫描完成... ({elapsed}/{max_wait_seconds}秒)")
    
    scan_wait_ms = int((time.time() - start_time) * 1000)
    print(f"[WARNING] 扫描超时（{scan_wait_ms}ms），可能未完成")
    return False, scan_wait_ms


def _trigger_scan_with_lock(
    client,
    detector_id: str,
    detector: dict,
    baseline_timestamp_ms: int,
    baseline_count: int,
    max_wait_seconds: int
) -> dict[str, Any]:
    """
    使用锁机制触发扫描
    
    返回: {
        "scan_requested": bool,
        "scan_completed": bool,
        "scan_wait_ms": int,
        "source": str
    }
    """
    import time
    from .trigger_lock import get_detector_lock, register_trigger, complete_trigger
    
    # 单飞模式：检查是否有其他线程正在触发
    is_leader, wait_event = register_trigger(detector_id, timeout_seconds=max_wait_seconds)
    
    if not is_leader:
        print(f"[INFO] 其他线程正在触发detector，等待结果...")
        wait_event.wait(timeout=max_wait_seconds)
        print(f"[INFO] 等待完成，继续查询findings")
        return {
            "scan_requested": False,
            "scan_completed": False,
            "scan_wait_ms": 0,
            "source": "cached_findings"
        }
    
    print(f"[INFO] 当前线程负责触发detector: {detector_id}")
    detector_lock = get_detector_lock(detector_id)
    original_schedule = None
    schedule_was_shortened = False
    
    try:
        with detector_lock:
            # 确保detector已启用
            _enable_detector_if_needed(client, detector_id, detector)
            
            # 手动触发扫描：Security Analytics 的 workflow 执行依赖 Alerting 监控配置系统索引，
            # 在部分 OpenSearch 版本/配置中，即使用 admin + all_access 也可能触发
            # `alerting_exception ... indices:data/read/get[s]`（系统索引访问限制）。
            #
            # 默认策略：优先使用 schedule 方式触发，避免 execute API 的权限/系统索引问题。
            # 如需优先尝试 workflow execute，可设置环境变量：OPENSEARCH_SA_PREFER_WORKFLOW_EXECUTE=1
            prefer_workflow_execute = os.getenv("OPENSEARCH_SA_PREFER_WORKFLOW_EXECUTE", "0").lower() in (
                "1",
                "true",
                "yes",
                "on",
            )

            workflow_id = _get_workflow_id_for_detector(client, detector_id)
            execute_success = False

            if workflow_id and prefer_workflow_execute:
                print("[INFO] 找到workflow，尝试使用workflow _execute API手动触发...")
                execute_success = _execute_workflow_manually(client, workflow_id)
                if execute_success:
                    print("[INFO] Workflow手动触发成功，等待扫描完成...")
                    scan_completed, scan_wait_ms = _poll_for_scan_completion(
                        client, detector_id, baseline_timestamp_ms, baseline_count, max_wait_seconds
                    )
                    source = "triggered_scan_execute" if scan_completed else "cached_findings"
                else:
                    print("[INFO] Workflow _execute失败，将使用schedule方式触发...")
            elif workflow_id and not prefer_workflow_execute:
                print(
                    "[INFO] 已找到workflow，但默认跳过 execute（避免 alerting 系统索引权限限制），使用 schedule 方式触发。"
                )

            # 方式：使用 schedule 触发（同样有效）
            if not execute_success:
                if not workflow_id:
                    print("[INFO] 未找到workflow（这是正常的），使用schedule方式触发扫描...")

                original_schedule, schedule_was_shortened = _temporarily_shorten_schedule(
                    client, detector_id, detector
                )
                
                if schedule_was_shortened:
                    # 轮询确认扫描完成
                    scan_completed, scan_wait_ms = _poll_for_scan_completion(
                        client, detector_id, baseline_timestamp_ms, baseline_count, max_wait_seconds
                    )
                    source = "triggered_scan_schedule" if scan_completed else "cached_findings"
                else:
                    # schedule较短或强制触发失败，等待一个扫描周期
                    print("[INFO] Detector schedule较短或强制触发失败，等待自动扫描...")
                    # 等待一个扫描周期（至少30秒）
                    wait_seconds = max(DEFAULT_POLL_INTERVAL_SECONDS, 30)
                    time.sleep(wait_seconds)
                    # 轮询确认是否有新findings
                    scan_completed, scan_wait_ms = _poll_for_scan_completion(
                        client, detector_id, baseline_timestamp_ms, baseline_count, max_wait_seconds - wait_seconds
                    )
                    source = "triggered_scan_schedule" if scan_completed else "cached_findings"
        
        return {
            "scan_requested": True,
            "scan_completed": scan_completed,
            "scan_wait_ms": scan_wait_ms,
            "source": source
        }
    
    finally:
        # 确保恢复schedule
        if schedule_was_shortened and original_schedule:
            _restore_schedule(client, detector_id, original_schedule)
        
        # 标记触发完成
        complete_trigger(detector_id)


# ========== 辅助函数：增量处理状态管理 ==========

def _get_last_processed_timestamp(client, detector_id: str) -> Optional[datetime]:
    """
    获取上次处理findings的时间戳
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID
    
    返回：
    - 上次处理的时间戳（如果不存在则返回None）
    """
    from .index import INDEX_PATTERNS, get_index_name
    
    try:
        # 查询raw-findings索引中该detector的最新finding时间戳
        index_pattern = INDEX_PATTERNS["RAW_FINDINGS"]
        today = datetime.now(timezone.utc)
        
        # 查询最近7天的索引（避免遗漏跨天数据）
        latest_timestamp = None
        for days_back in range(7):
            check_date = datetime(today.year, today.month, today.day, tzinfo=timezone.utc) - timedelta(
                days=days_back
            )
            index_name = get_index_name(index_pattern, check_date)
            
            try:
                # 查询该索引中该detector的最新finding
                search_resp = client.transport.perform_request(
                    'POST',
                    f'/{index_name}/_search',
                    body={
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"custom.finding.detector_id": detector_id}},
                                    {"exists": {"field": "@timestamp"}}
                                ]
                            }
                        },
                        "size": 1,
                        "sort": [{"@timestamp": {"order": "desc"}}]
                    }
                )
                
                hits = search_resp.get('hits', {}).get('hits', [])
                if hits:
                    doc = hits[0].get('_source', {})
                    timestamp_str = doc.get('@timestamp')
                    ts = parse_datetime(timestamp_str)
                    if ts is not None and (latest_timestamp is None or ts > latest_timestamp):
                        latest_timestamp = ts
            except Exception:
                # 索引可能不存在，继续查询下一个
                continue
        
        return latest_timestamp
    except Exception:
        return None


def _filter_new_findings(findings: list[dict[str, Any]], last_timestamp: Optional[datetime]) -> list[dict[str, Any]]:
    """
    过滤出新的findings（时间戳大于last_timestamp）
    
    参数：
    - findings: findings列表
    - last_timestamp: 上次处理的时间戳
    
    返回：
    - 新的findings列表
    """
    if last_timestamp is None:
        # 如果没有上次处理时间，返回所有findings
        return findings

    if last_timestamp.tzinfo is None:
        last_timestamp = last_timestamp.replace(tzinfo=timezone.utc)
    
    new_findings = []
    for finding in findings:
        timestamp_value = finding.get('timestamp') or finding.get('@timestamp')
        if not timestamp_value:
            # 如果没有时间戳，保守处理：包含它
            new_findings.append(finding)
            continue
        
        finding_ts = parse_datetime(timestamp_value)
        if finding_ts is None:
            new_findings.append(finding)
            continue

        if finding_ts > last_timestamp:
            new_findings.append(finding)
    
    return new_findings


# ========== 辅助函数：查询和存储findings ==========

def _fetch_and_store_findings(client, detector_id: str, only_new: bool = True) -> dict[str, Any]:
    """
    查询findings并存储（支持增量处理）
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID
    - only_new: 是否只处理新的findings（默认True，避免重复处理）
    
    返回: {
        "success": bool,
        "findings_count": int,        # 查询到的findings总数
        "new_findings_count": int,     # 新的findings数量（过滤后）
        "stored": int,
        "failed": int,
        "duplicated": int,
        "message": str
    }
    """
    from .storage import store_events
    
    # 获取上次处理的时间戳
    last_timestamp = None
    if only_new:
        last_timestamp = _get_last_processed_timestamp(client, detector_id)
        if last_timestamp:
            print(f"[INFO] 上次处理时间: {last_timestamp.isoformat()}，将只处理新findings")
        else:
            print(f"[INFO] 未找到上次处理时间，将处理所有findings")
    
    try:
        findings_resp = client.transport.perform_request(
            'GET',
            SA_FINDINGS_SEARCH_API,
            params={'detector_id': detector_id, 'size': 1000}
        )
        findings = findings_resp.get('findings', [])
        print(f"[INFO] 从Security Analytics API获取到 {len(findings)} 个findings")
        
    except Exception as api_error:
        error_msg = str(api_error)
        if '404' in error_msg or 'not found' in error_msg.lower():
            return {
                "success": False,
                "message": "Security Analytics 插件未安装或未启用",
                "findings_count": 0,
                "new_findings_count": 0,
                "stored": 0,
                "failed": 0,
                "duplicated": 0
            }
        raise
    
    if not findings:
        return {
            "success": True,
            "message": "没有findings",
            "findings_count": 0,
            "new_findings_count": 0,
            "stored": 0,
            "failed": 0,
            "duplicated": 0
        }
    
    # 过滤出新的findings（如果启用增量处理）
    new_findings = findings
    if only_new and last_timestamp:
        new_findings = _filter_new_findings(findings, last_timestamp)
        skipped_count = len(findings) - len(new_findings)
        if skipped_count > 0:
            print(f"[INFO] 跳过 {skipped_count} 个已处理的findings，剩余 {len(new_findings)} 个新findings")
    
    if not new_findings:
        return {
            "success": True,
            "message": "没有新的findings需要处理",
            "findings_count": len(findings),
            "new_findings_count": 0,
            "stored": 0,
            "failed": 0,
            "duplicated": 0
        }
    
    # 转换为ECS格式并存储
    converted_findings = []
    for finding in new_findings:
        try:
            ecs_finding = _convert_security_analytics_finding_to_ecs(finding)
            converted_findings.append(ecs_finding)
        except Exception as convert_error:
            print(f"[WARNING] 转换finding失败，跳过: {convert_error}")
            continue
    
    if not converted_findings:
        return {
            "success": True,
            "message": "没有可转换的findings",
            "findings_count": len(findings),
            "new_findings_count": len(new_findings),
            "stored": 0,
            "failed": 0,
            "duplicated": 0
        }
    
    result = store_events(converted_findings)
    
    return {
        "success": True,
        "message": f"成功读取并存储 {result['success']} 条findings（共查询到 {len(findings)} 条，其中 {len(new_findings)} 条为新findings）",
        "findings_count": len(findings),
        "new_findings_count": len(new_findings),
        "stored": result['success'],
        "failed": result.get('failed', 0),
        "duplicated": result.get('duplicated', 0)
    }


def run_security_analytics(
    trigger_scan: bool = True,
    max_wait_seconds: int = 60,
    force_scan: bool = False,
) -> dict[str, Any]:
    """
    运行 OpenSearch Security Analytics 检测并读取结果写入 raw-findings-*
    
    改进策略：
    1. **优先查询已有findings**（策略2，默认路径）
    2. **仅在必要时触发新扫描**（策略1，当findings过旧或为空时）
    3. **使用锁防止并发冲突**
    4. **轮询确认扫描完成**（而不是固定sleep）
    5. **确保schedule恢复**（try/finally）
    6. **增量处理**：自动跳过已处理的findings，只处理新的（基于时间戳）
    
    参数：
    - trigger_scan: 是否允许触发新扫描（默认True，按需触发）
    - max_wait_seconds: 触发扫描后的最大等待时间（默认60秒）
    - force_scan: 是否强制触发一次扫描（默认False）。当你明确需要“立刻触发”时使用。
    
    返回：
    - success: 是否成功
    - findings_count: 查询到的findings总数
    - new_findings_count: 新的findings数量（已过滤重复）
    - stored: 存储成功的数量
    - scan_requested: 是否请求了新扫描
    - scan_completed: 扫描是否完成（通过轮询确认）
    - scan_wait_ms: 实际等待时间（毫秒）
    - source: "triggered_scan_execute" | "triggered_scan_schedule" | "cached_findings" | "no_findings"
    
    增量处理说明：
    - 函数会自动查询raw-findings索引中该detector的最新finding时间戳
    - 只处理时间戳大于上次处理时间的findings
    - 避免重复处理已分析的数据，提高效率
    """
    from .trigger_lock import complete_trigger
    
    client = get_client()
    detector_id = None
    
    try:
        # 步骤1: 获取detector ID
        detector_id = _get_detector_id(client)
        if not detector_id:
            return {
                "success": False,
                "message": "未找到detector",
                "findings_count": 0,
                "stored": 0,
                "scan_requested": False,
                "scan_completed": False,
                "scan_wait_ms": 0,
                "source": "no_findings"
            }
        
        # 步骤2: 查询已有findings的时间戳和数量
        baseline_timestamp_ms, baseline_count = _get_latest_findings_timestamp(client, detector_id)
        findings_age_minutes = None
        
        if baseline_count > 0:
            print(f"[INFO] 发现已有findings: {baseline_count} 个")
            if baseline_timestamp_ms > 0:
                # 计算findings年龄（分钟）
                current_timestamp_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
                findings_age_minutes = (current_timestamp_ms - baseline_timestamp_ms) / 1000 / 60
                print(f"[INFO] 最新finding时间戳: {baseline_timestamp_ms}（{findings_age_minutes:.1f}分钟前）")
        
        # 步骤3: 判断是否需要触发新扫描
        need_trigger = False
        if not trigger_scan:
            print("[INFO] trigger_scan=False，跳过触发扫描，仅使用已有findings（如有）")
            need_trigger = False
        elif force_scan:
            print("[INFO] force_scan=True，强制触发一次新扫描")
            need_trigger = True
        else:
            if baseline_count == 0:
                print("[INFO] 没有findings，需要触发新扫描")
                need_trigger = True
            elif findings_age_minutes is not None and findings_age_minutes > 5:
                print(f"[INFO] Findings过旧（{findings_age_minutes:.1f}分钟前），需要触发新扫描")
                need_trigger = True
            else:
                if findings_age_minutes is not None:
                    print(f"[INFO] Findings较新（{findings_age_minutes:.1f}分钟前），使用已有findings")
                else:
                    print("[INFO] Findings时间戳不可用，使用已有findings；如需强制触发请使用 force_scan=True")
        
        source = "cached_findings" if baseline_count > 0 else "no_findings"
        
        # 步骤4: 如果需要触发，执行触发逻辑
        scan_info = {
            "scan_requested": False,
            "scan_completed": False,
            "scan_wait_ms": 0,
            "source": source
        }
        
        if need_trigger:
            detector = _get_detector_details(client, detector_id)
            if detector:
                try:
                    scan_info = _trigger_scan_with_lock(
                        client, detector_id, detector, baseline_timestamp_ms, baseline_count, max_wait_seconds
                    )
                except Exception as trigger_error:
                    print(f"[WARNING] 触发检测时出错: {trigger_error}")
                    complete_trigger(detector_id)
            else:
                print(f"[WARNING] 无法获取detector详情，跳过触发")
        
        # 步骤5: 查询并存储findings（增量处理，自动跳过已处理的）
        storage_result = _fetch_and_store_findings(client, detector_id, only_new=True)
        
        return {
            "success": storage_result["success"],
            "message": storage_result["message"],
            "findings_count": storage_result["findings_count"],
            "new_findings_count": storage_result.get("new_findings_count", storage_result["findings_count"]),
            "stored": storage_result["stored"],
            "failed": storage_result.get("failed", 0),
            "duplicated": storage_result.get("duplicated", 0),
            **scan_info
        }
    
    except Exception as error:
        error_msg = str(error)
        print(f"[ERROR] Security Analytics检测失败: {error_msg}")
        
        # 确保清理
        if detector_id:
            complete_trigger(detector_id)
        
        return {
            "success": False,
            "message": f"Security Analytics检测失败: {error_msg}",
            "findings_count": 0,
            "stored": 0,
            "scan_requested": False,
            "scan_completed": False,
            "scan_wait_ms": 0,
            "source": "no_findings"
        }


def run_data_analysis(trigger_scan: bool = True, force_scan: bool = False) -> dict[str, Any]:
    """
    数据分析主函数
    1. 运行 Security Analytics 检测（按需触发）
    2. 告警融合去重（Raw → Canonical）
    
    参数：
    - trigger_scan: 是否允许触发Security Analytics扫描（默认True，按需触发模式）
    - force_scan: 是否强制触发一次扫描（默认False）
    """
    # Step 1: 运行 Security Analytics 检测（按需触发）
    detection_result = run_security_analytics(trigger_scan=trigger_scan, force_scan=force_scan)

    # Step 2: 告警融合去重
    deduplication_result = deduplicate_findings()

    return {
        "detection": detection_result,
        "deduplication": deduplication_result,
    }
