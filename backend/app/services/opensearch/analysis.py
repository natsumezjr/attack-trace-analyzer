# OpenSearch 数据分析模块
# 包含 Security Analytics 检测调用和告警融合去重

"""
OpenSearch 数据分析模块

包含 Security Analytics 检测调用和告警融合去重功能。
"""

import hashlib
from typing import Any, Optional
from datetime import datetime, timedelta

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
ALERTING_WORKFLOWS_SEARCH_API = "/_plugins/_alerting/monitors/_search"
ALERTING_WORKFLOW_EXECUTE_API = "/_plugins/_alerting/workflows/{workflow_id}/_execute"

# 缓存时间窗口（秒）：如果findings在5分钟内，直接使用，不触发新扫描
FINDINGS_CACHE_WINDOW_SECONDS = 300  # 5分钟

# 默认超时设置
DEFAULT_SCAN_TIMEOUT_SECONDS = 60  # 扫描超时时间（秒）
DEFAULT_POLL_INTERVAL_SECONDS = 2  # 轮询间隔（秒）


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
    
    # 处理不同格式的时间戳
    if timestamp_value:
        if isinstance(timestamp_value, str):
            # ISO格式字符串
            timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
            timestamp_ms = int(timestamp.timestamp() * 1000)
        elif isinstance(timestamp_value, datetime):
            # datetime对象
            timestamp_ms = int(timestamp_value.timestamp() * 1000)
        elif isinstance(timestamp_value, (int, float)):
            # 整数或浮点数时间戳
            # 判断是秒还是毫秒（毫秒通常 > 1e12）
            if timestamp_value > 1e12:
                timestamp_ms = int(timestamp_value)  # 已经是毫秒
            else:
                timestamp_ms = int(timestamp_value * 1000)  # 秒转毫秒
        else:
            # 未知格式，使用当前时间
            timestamp_ms = int(datetime.now().timestamp() * 1000)
    else:
        # 没有时间戳，使用当前时间
        timestamp_ms = int(datetime.now().timestamp() * 1000)
    
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

    # 根据规则来源推断
    rule_id = finding.get("rule", {}).get("id") or finding.get("rule.id")
    if rule_id:
        rule_id_lower = rule_id.lower()
        if "wazuh" in rule_id_lower:
            return "wazuh"
        if "falco" in rule_id_lower:
            return "falco"
        if "suricata" in rule_id_lower:
            return "suricata"
        if "sigma" in rule_id_lower or "opensearch" in rule_id_lower:
            return "opensearch-security-analytics"

    return "unknown"


def merge_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """合并多个 Raw Findings 为一条 Canonical Finding"""
    if len(findings) == 0:
        raise ValueError("无法合并空数组")

    # 使用第一个 finding 作为基础
    import copy

    base = copy.deepcopy(findings[0])

    # 合并 providers
    providers = set()
    for f in findings:
        provider = extract_provider(f)
        providers.add(provider)
        # 如果 finding 有 providers 数组，也添加进去
        f_custom = f.get("custom", {})
        f_finding = f_custom.get("finding", {})
        f_providers = f_finding.get("providers")
        if isinstance(f_providers, list):
            providers.update(f_providers)

    # 合并 evidence.event_ids
    event_ids = set()
    for f in findings:
        event = f.get("event", {})
        if event.get("id"):
            event_ids.add(event.get("id"))
        if f.get("event.id"):
            event_ids.add(f.get("event.id"))
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
    base["custom"]["finding"]["providers"] = list(providers)

    if "evidence" not in base["custom"]:
        base["custom"]["evidence"] = {}
    base["custom"]["evidence"]["event_ids"] = list(event_ids)

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
    today = datetime.now()
    raw_index_name = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
    canonical_index_name = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)

    try:
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

                if "event" in single:
                    single["event"]["dataset"] = "finding.canonical"
                    single["event"]["kind"] = "alert"
                else:
                    single["event.dataset"] = "finding.canonical"
                    single["event.kind"] = "alert"

                canonical_findings.append(single)

        # 批量写入 Canonical Findings
        if len(canonical_findings) > 0:
            documents = [
                {
                    "id": f.get("event", {}).get("id") or f.get("event.id"),
                    "document": f,
                }
                for f in canonical_findings
            ]

            result = bulk_index(canonical_index_name, documents)
            # 刷新索引，使新写入的 Canonical Findings 立即可搜索
            if result.get("success", 0) > 0:
                refresh_index(canonical_index_name)

            return {
                "total": len(raw_findings),
                "merged": merged_count,
                "canonical": len(canonical_findings),
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
    from datetime import datetime
    
    # 提取基本信息
    finding_id = finding.get('id', f"sa-finding-{datetime.now().timestamp()}")
    timestamp = finding.get('timestamp', datetime.now().isoformat())
    
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
            "dataset": "finding.raw",
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
                "providers": ["security-analytics"],  # 标记来源
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
    
    return ecs_finding


def _get_workflow_id_for_detector(client, detector_id: str) -> Optional[str]:
    """
    根据detector_id获取对应的workflow_id
    
    Security Analytics会为每个detector创建一个composite workflow
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID
    
    返回：
    - workflow_id: 如果找到则返回workflow ID，否则返回None
    """
    try:
        # 查询workflow，找到名称匹配detector的workflow
        workflow_resp = client.transport.perform_request(
            'POST',
            ALERTING_WORKFLOWS_SEARCH_API,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "workflow"}},
                            {"term": {"workflow_type": "composite"}},
                            {"term": {"owner": "security_analytics"}}
                        ]
                    }
                },
                "size": 10
            }
        )
        
        hits = workflow_resp.get('hits', {}).get('hits', [])
        for hit in hits:
            workflow_source = hit.get('_source', {})
            # workflow名称通常与detector名称相同
            # 或者可以通过delegate monitor关联
            workflow_id = hit.get('_id')
            # 简单策略：返回第一个匹配的workflow（通常只有一个）
            return workflow_id
        
        return None
    except Exception:
        return None


def _get_latest_findings_count(client, detector_id: str) -> int:
    """
    使用Security Analytics的findings API获取findings数量
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID
    
    返回：
    - findings数量（如果查询失败则返回0）
    """
    try:
        findings_resp = client.transport.perform_request(
            'GET',
            SA_FINDINGS_SEARCH_API,
            params={
                'detector_id': detector_id,
                'size': 0  # 只要总数
            }
        )
        
        return findings_resp.get('total_findings', 0)
    except Exception:
        return 0


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
    """判断是否需要触发新扫描"""
    return trigger_scan and baseline_count == 0


# ========== 辅助函数：触发扫描相关 ==========

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
            client.transport.perform_request(
                'PUT',
                SA_DETECTOR_UPDATE_API.format(detector_id=detector_id),
                body={**detector, "schedule": temp_schedule, "enabled": True}
            )
            print(f"[INFO] Schedule已临时设置为1分钟")
            return original_schedule, True
        except Exception as e:
            print(f"[WARNING] 设置临时schedule失败: {e}")
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
    baseline_count: int, 
    max_wait_seconds: int
) -> tuple[bool, int]:
    """
    轮询确认扫描完成
    
    返回: (scan_completed, scan_wait_ms)
    """
    import time
    
    start_time = time.time()
    print(f"[INFO] 开始轮询确认扫描完成（最多等待{max_wait_seconds}秒）...")
    
    while (time.time() - start_time) < max_wait_seconds:
        time.sleep(DEFAULT_POLL_INTERVAL_SECONDS)
        
        current_count = _get_latest_findings_count(client, detector_id)
        
        if current_count > baseline_count:
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
            
            # 临时缩短schedule
            original_schedule, schedule_was_shortened = _temporarily_shorten_schedule(
                client, detector_id, detector
            )
            
            if schedule_was_shortened:
                # 轮询确认扫描完成
                scan_completed, scan_wait_ms = _poll_for_scan_completion(
                    client, detector_id, baseline_count, max_wait_seconds
                )
                source = "triggered_scan" if scan_completed else "cached_findings"
            else:
                print(f"[INFO] Detector schedule已较短，等待自动扫描...")
                time.sleep(DEFAULT_POLL_INTERVAL_SECONDS)
                scan_completed = False
                scan_wait_ms = 0
                source = "cached_findings"
        
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
        today = datetime.now()
        
        # 查询最近7天的索引（避免遗漏跨天数据）
        latest_timestamp = None
        for days_back in range(7):
            check_date = datetime(today.year, today.month, today.day) - timedelta(days=days_back)
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
                    if timestamp_str:
                        if isinstance(timestamp_str, str):
                            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                        elif isinstance(timestamp_str, datetime):
                            ts = timestamp_str
                        else:
                            continue
                        
                        if latest_timestamp is None or ts > latest_timestamp:
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
    
    new_findings = []
    for finding in findings:
        timestamp_value = finding.get('timestamp') or finding.get('@timestamp')
        if not timestamp_value:
            # 如果没有时间戳，保守处理：包含它
            new_findings.append(finding)
            continue
        
        # 解析时间戳
        try:
            if isinstance(timestamp_value, str):
                finding_ts = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
            elif isinstance(timestamp_value, datetime):
                finding_ts = timestamp_value
            elif isinstance(timestamp_value, (int, float)):
                # 假设是毫秒时间戳
                if timestamp_value > 1e12:
                    finding_ts = datetime.fromtimestamp(timestamp_value / 1000)
                else:
                    finding_ts = datetime.fromtimestamp(timestamp_value)
            else:
                # 无法解析，保守处理：包含它
                new_findings.append(finding)
                continue
            
            # 只包含时间戳大于上次处理时间的finding
            # 使用微秒精度比较，避免边界问题
            if finding_ts > last_timestamp:
                new_findings.append(finding)
        except Exception:
            # 解析失败，保守处理：包含它
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


def run_security_analytics(trigger_scan: bool = True, max_wait_seconds: int = 60) -> dict[str, Any]:
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
    - trigger_scan: 是否允许触发新扫描（默认True）
    - max_wait_seconds: 触发扫描后的最大等待时间（默认60秒）
    
    返回：
    - success: 是否成功
    - findings_count: 查询到的findings总数
    - new_findings_count: 新的findings数量（已过滤重复）
    - stored: 存储成功的数量
    - scan_requested: 是否请求了新扫描
    - scan_completed: 扫描是否完成（通过轮询确认）
    - scan_wait_ms: 实际等待时间（毫秒）
    - source: "fresh_scan" | "cached_findings" | "no_findings"
    
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
        
        # 步骤2: 查询已有findings数量
        baseline_count = _get_latest_findings_count(client, detector_id)
        if baseline_count > 0:
            print(f"[INFO] 发现已有findings: {baseline_count} 个")
        
        # 步骤3: 判断是否需要触发新扫描
        need_trigger = _should_trigger_scan(trigger_scan, baseline_count)
        source = "cached_findings" if baseline_count > 0 else "no_findings"
        
        if need_trigger:
            print(f"[INFO] 没有findings，需要触发新扫描")
        else:
            print(f"[INFO] 已有findings: {baseline_count} 个，使用已有findings")
        
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
                        client, detector_id, detector, baseline_count, max_wait_seconds
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


def run_data_analysis(trigger_scan: bool = True) -> dict[str, Any]:
    """
    数据分析主函数
    1. 运行 Security Analytics 检测（按需触发）
    2. 告警融合去重（Raw → Canonical）
    
    参数：
    - trigger_scan: 是否触发Security Analytics扫描（默认True，按需触发模式）
    """
    # Step 1: 运行 Security Analytics 检测（按需触发）
    detection_result = run_security_analytics(trigger_scan=trigger_scan)

    # Step 2: 告警融合去重
    deduplication_result = deduplicate_findings()

    return {
        "detection": detection_result,
        "deduplication": deduplication_result,
    }
