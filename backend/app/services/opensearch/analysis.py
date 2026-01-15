# OpenSearch 数据分析模块
# 基于 Correlation Rules 的跨事件关联分析

"""
OpenSearch 数据分析模块

专注于使用 Correlation Rules 实现多个事件之间的跨事件分析。
不再使用 Security Analytics 的单点检测功能，而是通过 correlation rules 
来关联多个 findings/events，生成高层攻击场景（如横向移动）。
"""

import hashlib
from typing import Any, Optional, List, Dict
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from app.core.time import parse_datetime, to_rfc3339, utc_now_rfc3339

from .client import get_client, search, bulk_index, refresh_index, index_exists
from .index import INDEX_PATTERNS, get_index_name

# ========== 常量定义 ==========

# 时间窗口（分钟），用于时间桶计算
TIME_WINDOW_MINUTES = 3

# Security Analytics API 路径
SA_DETECTORS_SEARCH_API = "/_plugins/_security_analytics/detectors/_search"
SA_DETECTOR_GET_API = "/_plugins/_security_analytics/detectors/{detector_id}"
SA_DETECTOR_UPDATE_API = "/_plugins/_security_analytics/detectors/{detector_id}"
SA_FINDINGS_SEARCH_API = "/_plugins/_security_analytics/findings/_search"
SA_RULES_SEARCH_API = "/_plugins/_security_analytics/rules/_search"

# Alerting Monitor API 路径
ALERTING_MONITOR_EXECUTE_API = "/_plugins/_alerting/monitors/{monitor_id}/_execute"

# Detectors Config 索引（用于查询 monitor_id）
DETECTORS_CONFIG_INDEX = ".opensearch-sap-detectors-config"

# 默认超时设置
DEFAULT_SCAN_TIMEOUT_SECONDS = 10  # 扫描超时时间（秒）- 缩短为10秒，因为每5秒轮询一次
DEFAULT_POLL_INTERVAL_SECONDS = 1  # 轮询间隔（秒）- 可以设置得很短（1秒或更短），用于快速检查扫描完成状态

# 数据查询时间窗口（秒）- 只查询最近N秒的数据
DATA_QUERY_TIME_WINDOW_SECONDS = 5  # 默认5秒，与轮询周期一致

# Correlation Rules API 路径
CORRELATION_RULES_API = "/_plugins/_security_analytics/correlation/rules"
CORRELATION_RESULTS_API = "/_plugins/_security_analytics/correlations"
CORRELATION_FINDING_CORRELATE_API = "/_plugins/_security_analytics/findings/correlate"

# Correlation 时间窗口（分钟）
CORRELATION_TIME_WINDOW_MINUTES = 30  # 默认 30 分钟

# 横向移动检测的 Technique ID
LATERAL_MOVEMENT_TECHNIQUE_ID = "T1021"
LATERAL_MOVEMENT_TACTIC_ID = "TA0008"
LATERAL_MOVEMENT_TACTIC_NAME = "Lateral Movement"

# ========== ATT&CK Tactic映射表 ==========

# ATT&CK Tactic映射表（从technique ID到tactic ID）
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
    # Command and Control (TA0011)
    "T1071": "TA0011",  # Application Layer Protocol
    "T1095": "TA0011",  # Non-Application Layer Protocol
    # Impact (TA0040)
    "T1531": "TA0040",  # Account Access Removal
    "T1565": "TA0040",  # Data Manipulation
    "T1489": "TA0040",  # Service Stop
}

# ATT&CK Tactic名称映射
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

# ========== 辅助函数 ==========

def fingerprint_id_from_key(fingerprint_key: str) -> str:
    """
    将用于分组/融合的"原始指纹 key"转换为 docs 约定的 custom.finding.fingerprint。
    """
    digest = hashlib.sha1(fingerprint_key.encode("utf-8")).hexdigest()
    return f"fp-{digest}"


def _get_tactic_from_technique(technique_id: str) -> str:
    """从technique ID推断tactic ID"""
    if technique_id in TECHNIQUE_TO_TACTIC_MAP:
        return TECHNIQUE_TO_TACTIC_MAP[technique_id]
    base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
    if base_id in TECHNIQUE_TO_TACTIC_MAP:
        return TECHNIQUE_TO_TACTIC_MAP[base_id]
    return "TA0000"


def _get_tactic_id_from_name(tactic_name: str) -> str:
    """从tactic名称获取tactic ID"""
    return TACTIC_NAME_TO_ID_MAP.get(tactic_name.lower(), "TA0000")


def _get_tactic_name(tactic_id: str) -> str:
    """从tactic ID获取tactic名称"""
    return TACTIC_ID_TO_NAME_MAP.get(tactic_id, "Unknown")


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
    custom = finding.get("custom", {})
    finding_obj = custom.get("finding", {})
    providers = finding_obj.get("providers", [])
    if isinstance(providers, list) and len(providers) > 0:
        return providers[0]
    
    # 从 dataset 推断
    dataset = finding.get("event", {}).get("dataset") or finding.get("event.dataset", "")
    if "correlation" in dataset.lower():
        return "correlation_rules"
    
    return "unknown"


def merge_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """合并多个 Raw Findings 为一条 Canonical Finding"""
    if len(findings) == 0:
        raise ValueError("无法合并空数组")

    import copy
    base = copy.deepcopy(findings[0])

    # 合并 providers
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

    # 合并 evidence.event_ids
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

    # confidence 可按来源数量上调
    confidence = min(0.5 + (len(providers) * 0.15), 1.0)
    base["custom"]["confidence"] = confidence

    # 生成新的 event.id（基于指纹）
    fingerprint = generate_fingerprint(base)
    base["custom"]["finding"]["fingerprint"] = fingerprint_id_from_key(fingerprint)
    hash_value = hashlib.sha256(fingerprint.encode()).hexdigest()[:16]
    if "event" not in base:
        base["event"] = {}
    base["event"]["id"] = f"canonical-{hash_value}"

    return base


# ========== 分级判断函数 ==========

def classify_privilege_escalation_level(event: Dict[str, Any]) -> tuple[int, float]:
    """
    分级判断提权事件（基于单条 event）
    
    实现思路：
    - Level 1: 提权尝试（基于进程特征）- 置信度 0.3-0.5
    - Level 2: 可疑提权行为（提权尝试 + 父进程异常）- 置信度 0.5-0.7
    - Level 3: 提权成功（提权尝试 + 后续高权限操作）- 置信度 0.8-1.0
    
    注意：
    - Level 1 和 Level 2 可以在单条 event 中判断
    - Level 3 需要多事件关联，在 correlation 阶段无法单独判断
    
    参数：
    - event: 单个 event 文档（_source）
    
    返回: (level, confidence) tuple
        - level: 0=不是提权, 1=尝试, 2=可疑, 3=成功（单条event无法判断3）
        - confidence: 置信度 0.0-1.0
    """
    event_source = event if isinstance(event, dict) else {}
    
    # 提取进程信息
    process = event_source.get('process', {})
    process_name = process.get('name', '') or ''
    command_line = process.get('command_line', '') or ''
    parent = process.get('parent', {})
    parent_name = parent.get('name', '') or ''
    parent_executable = parent.get('executable', '') or ''
    
    # 提权关键词
    privilege_keywords = ['privilege', 'elevate', 'runas', 'sudo', 'su ', 'admin', 'system']
    
    # 检查是否包含提权关键词
    has_privilege_keyword = False
    if process_name:
        has_privilege_keyword = any(kw in process_name.lower() for kw in privilege_keywords)
    if not has_privilege_keyword and command_line:
        has_privilege_keyword = any(kw in command_line.lower() for kw in privilege_keywords)
    
    if not has_privilege_keyword:
        return (0, 0.0)  # 不是提权相关事件
    
    # Level 1: 提权尝试（基于进程特征）
    level = 1
    confidence = 0.4  # 基础置信度
    
    # Level 2: 可疑提权行为（提权尝试 + 父进程异常）
    # 父进程异常：从非正常父进程启动（如从浏览器、邮件客户端启动提权工具）
    # Linux/Unix 可疑父进程列表（已移除 Windows 进程名）
    suspicious_parents = ['chrome', 'firefox', 'chromium', 'thunderbird', 'evolution', 'geary']
    if parent_name:
        parent_lower = parent_name.lower()
        if any(sp in parent_lower for sp in suspicious_parents):
            level = 2
            confidence = 0.6  # 父进程异常，提高置信度
    
    # Level 3: 提权成功（需要后续事件，单条 event 无法判断）
    # 这个级别需要在 correlation 后处理阶段判断
    # 如果后续有服务创建、计划任务创建等事件，可以提升到 Level 3
    
    return (level, confidence)


# ========== Security Analytics 功能 ==========

def _get_tactic_from_technique(technique_id: str) -> str:
    """从technique ID推断tactic ID"""
    if technique_id in TECHNIQUE_TO_TACTIC_MAP:
        return TECHNIQUE_TO_TACTIC_MAP[technique_id]
    base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
    if base_id in TECHNIQUE_TO_TACTIC_MAP:
        return TECHNIQUE_TO_TACTIC_MAP[base_id]
    return "TA0000"


def _get_tactic_id_from_name(tactic_name: str) -> str:
    """从tactic名称获取tactic ID"""
    return TACTIC_NAME_TO_ID_MAP.get(tactic_name.lower(), "TA0000")


def _get_tactic_name(tactic_id: str) -> str:
    """从tactic ID获取tactic名称"""
    return TACTIC_ID_TO_NAME_MAP.get(tactic_id, "Unknown")


def _convert_security_analytics_finding_to_ecs(finding: dict[str, Any]) -> dict[str, Any]:
    """
    将 Security Analytics 的 finding 转换为 ECS 格式的 Finding
    """
    finding_id = finding.get("id") or f"sa-finding-{int(datetime.now(timezone.utc).timestamp())}"
    timestamp = to_rfc3339(finding.get("timestamp")) or utc_now_rfc3339()
    
    detector = finding.get('detector', {})
    detector_id = detector.get('id', 'unknown')
    detector_name = detector.get('name', 'Security Analytics Detector')
    
    queries = finding.get('queries', [])
    rule_info = {}
    if queries:
        first_query = queries[0]
        rule_info = {
            "id": f"sa-rule-{detector_id}",
            "name": first_query.get('name', 'Security Analytics Rule'),
            "version": "1.0",
        }
    
    tactic_id = None
    tactic_name = None
    technique_id = None
    
    # 收集所有标签（从 finding 和 queries 中）
    all_tags = []
    
    # 方法1: 从 finding 的 tags 字段提取
    tags = finding.get('tags', [])
    all_tags.extend(tags)
    
    # 方法2: 从 queries 的 tags 字段提取（优先级更高，因为更具体）
    if queries:
        for query in queries:
            query_tags = query.get('tags', [])
            all_tags.extend(query_tags)
    
    # 优先查找 tactic name 标签（如 attack.command_and_control）
    tactic_name_tags = []
    technique_tags = []
    
    for tag in all_tags:
        if isinstance(tag, str) and tag.startswith('attack.'):
            parts = tag.split('.')
            if len(parts) >= 2:
                tag_value = parts[1]
                # 检查是否是 technique ID（如 attack.t1071.004）
                if tag_value.startswith('t') and len(tag_value) > 1:
                    # 提取完整的 technique ID（包括子技术，如 t1071.004）
                    if len(parts) > 2:
                        # 如果有子技术编号，拼接完整ID（如 t1071.004）
                        technique_tags.append(f"{tag_value}.{'.'.join(parts[2:])}")
                    else:
                        technique_tags.append(tag_value)
                # 检查是否是 tactic ID（如 attack.ta0011）- 跳过，因为我们需要从名称映射
                elif tag_value.startswith('ta') and len(tag_value) > 2:
                    continue
                # 否则是 tactic name（如 attack.command_and_control）
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
        # 转换为完整的 technique ID（如 t1071.004 -> T1071.004）
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
    
    threat_info = {
        "tactic": {
            "id": tactic_id or "TA0000",
            "name": tactic_name or "Unknown"
        }
    }
    
    if technique_id:
        threat_info["technique"] = {
            "id": technique_id,
            "name": "Security Analytics Detection"
        }
    
    document_list = finding.get('document_list', [])
    related_events = []
    host_info = {}
    
    if document_list:
        first_doc = document_list[0]
        if isinstance(first_doc, dict):
            if 'host' in first_doc:
                host_info = first_doc['host']
            elif 'host.id' in first_doc:
                host_info = {
                    "id": first_doc.get('host.id'),
                    "name": first_doc.get('host.name', 'unknown')
                }
            
            if 'event' in first_doc and 'id' in first_doc['event']:
                related_events.append(first_doc['event']['id'])
    
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
            "severity": finding.get('severity', 50),
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
                "providers": ["security_analytics"],
            },
            "confidence": finding.get('confidence', 0.7),
        },
        "host": host_info if host_info else {
            "id": "unknown",
            "name": "unknown"
        },
        "message": finding.get('description', f"Security Analytics detection from {detector_name}"),
    }
    
    if related_events:
        ecs_finding["custom"]["evidence"] = {
            "event_ids": related_events
        }
    
    try:
        fp_key = generate_fingerprint(ecs_finding)
        ecs_finding["custom"]["finding"]["fingerprint"] = fingerprint_id_from_key(fp_key)
    except Exception:
        pass
    
    return ecs_finding


def _get_all_monitor_ids(client, enabled_only: bool = False) -> list[str]:
    """
    从 .opensearch-sap-detectors-config 索引获取所有 monitor IDs
    
    按照推荐方法：
    1. 查询 .opensearch-sap-detectors-config 索引
    2. 解析 monitor_id 数组（保序去重）
    3. 按需过滤 enabled
    
    参数：
    - client: OpenSearch客户端
    - enabled_only: 是否只返回启用的detector的monitor IDs（默认False，返回所有）
    
    返回：
    - monitor_ids: monitor ID列表（已去重，保序）
    """
    monitor_ids = []
    seen = set()
    
    # 方法1: 从 .opensearch-sap-detectors-config 索引查询（推荐方法）
    try:
        # 先检查索引是否存在
        if not index_exists(DETECTORS_CONFIG_INDEX):
            print(f"[INFO] 索引 {DETECTORS_CONFIG_INDEX} 不存在，尝试备用方法")
            raise Exception(f"索引 {DETECTORS_CONFIG_INDEX} 不存在")
        
        # 按照推荐方法构建查询
        query_body = {
            "size": 1000,
            "query": {"term": {"type.keyword": "detector"}},
            "_source": [
                "name",
                "detector_type",
                "enabled",
                "monitor_id",
                "last_update_time"
            ]
        }
        
        response = client.transport.perform_request(
            'POST',
            f'/{DETECTORS_CONFIG_INDEX}/_search',
            body=query_body
        )
        
        hits = response.get('hits', {}).get('hits', [])
        total = response.get('hits', {}).get('total', {}).get('value', len(hits))
        print(f"[INFO] 从 {DETECTORS_CONFIG_INDEX} 索引查询到 {total} 个detector配置")
        
        # 解析 monitor_id
        for hit in hits:
            src = hit.get('_source', {})
            
            # 只取 type == "detector"
            if src.get('type') != 'detector':
                continue
            
            # 按需过滤 enabled
            if enabled_only and not src.get('enabled', False):
                continue
            
            # monitor_id 可能是数组或单个值
            mids = src.get('monitor_id')
            if mids is None:
                continue
            
            if isinstance(mids, list):
                for mid in mids:
                    if mid and mid not in seen:
                        seen.add(mid)
                        monitor_ids.append(mid)
            elif mids:
                if mids not in seen:
                    seen.add(mids)
                    monitor_ids.append(mids)
        
        if monitor_ids:
            print(f"[INFO] 从配置索引获取到 {len(monitor_ids)} 个唯一的 monitor IDs")
            return monitor_ids
            
    except Exception as e:
        print(f"[INFO] 从配置索引查询monitor IDs失败: {e}")
        print(f"[INFO] 尝试备用方法：从detector详情中获取monitor_id")
    
    # 方法2: 备用方案 - 从detector详情中获取monitor_id
    try:
        detectors_resp = client.transport.perform_request(
            'POST',
            SA_DETECTORS_SEARCH_API,
            body={
                "query": {"match_all": {}},
                "size": 1000
            }
        )
        detector_hits = detectors_resp.get('hits', {}).get('hits', [])
        
        for hit in detector_hits:
            detector_id = hit.get('_id')
            detector_source = hit.get('_source', {})
            
            # 检查detector是否启用
            if enabled_only:
                enabled_value = detector_source.get('enabled')
                if enabled_value is None:
                    detector_obj = detector_source.get('detector')
                    if isinstance(detector_obj, dict):
                        enabled_value = detector_obj.get('enabled')
                
                if isinstance(enabled_value, str):
                    enabled_value = enabled_value.lower() in ('true', '1', 'yes')
                elif enabled_value is None:
                    enabled_value = False
                else:
                    enabled_value = bool(enabled_value)
                
                if not enabled_value:
                    continue
            
            # 尝试从detector详情中获取monitor_id
            monitor_id = detector_source.get('monitor_id') or detector_source.get('monitor_ids')
            
            if monitor_id:
                if isinstance(monitor_id, list):
                    for mid in monitor_id:
                        if mid and mid not in seen:
                            seen.add(mid)
                            monitor_ids.append(mid)
                else:
                    if monitor_id not in seen:
                        seen.add(monitor_id)
                        monitor_ids.append(monitor_id)
            else:
                # 如果detector详情中没有，尝试通过detector ID获取完整详情
                try:
                    detector_detail = _get_detector_details(client, detector_id)
                    if detector_detail:
                        monitor_id = detector_detail.get('monitor_id') or detector_detail.get('monitor_ids')
                        if monitor_id:
                            if isinstance(monitor_id, list):
                                for mid in monitor_id:
                                    if mid and mid not in seen:
                                        seen.add(mid)
                                        monitor_ids.append(mid)
                            else:
                                if monitor_id not in seen:
                                    seen.add(monitor_id)
                                    monitor_ids.append(monitor_id)
                except Exception:
                    pass
        
        if monitor_ids:
            print(f"[INFO] 从detector详情获取到 {len(monitor_ids)} 个唯一的 monitor IDs")
            return monitor_ids
        
    except Exception as e:
        print(f"[WARNING] 从detector详情获取monitor IDs失败: {e}")
    
    print(f"[WARNING] 未找到任何 monitor IDs")
    return []


def _execute_monitors(
    client,
    monitor_ids: list[str],
    max_wait_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS
) -> dict[str, Any]:
    """
    直接执行 monitors（按照推荐方法）
    
    对每个 monitor_id 调用：
    POST _plugins/_alerting/monitors/{monitor_id}/_execute
    
    参数：
    - client: OpenSearch客户端
    - monitor_ids: monitor ID列表
    - max_wait_seconds: 每个monitor的最大等待时间（秒）
    
    返回：
    - {
        "executed": int,      # 成功执行的monitor数量
        "failed": int,         # 失败的monitor数量
        "results": list       # 每个monitor的执行结果
      }
    """
    results = []
    executed = 0
    failed = 0
    
    print(f"[INFO] 开始执行 {len(monitor_ids)} 个 monitors...")
    
    for i, monitor_id in enumerate(monitor_ids, 1):
        try:
            # 调用 execute API
            response = client.transport.perform_request(
                'POST',
                ALERTING_MONITOR_EXECUTE_API.format(monitor_id=monitor_id),
                timeout=max_wait_seconds
            )
            
            # 检查响应状态
            if isinstance(response, dict):
                status_code = response.get('status', 200)
                ok = status_code < 300
            elif hasattr(response, 'status_code'):
                status_code = response.status_code
                ok = status_code < 300
            else:
                status_code = 200
                ok = True
            
            if ok:
                executed += 1
                print(f"  [{i}/{len(monitor_ids)}] [OK] {monitor_id[:50]}... (OK)")
            else:
                failed += 1
                error_text = str(response)[:300] if isinstance(response, (dict, str)) else ""
                print(f"  [{i}/{len(monitor_ids)}] [FAIL] {monitor_id[:50]}... (FAIL {status_code})")
                if error_text:
                    print(f"      错误: {error_text}")
            
            results.append({
                "monitor_id": monitor_id,
                "success": ok,
                "status_code": status_code
            })
            
        except Exception as e:
            failed += 1
            error_msg = str(e)
            print(f"  [{i}/{len(monitor_ids)}] [ERROR] {monitor_id[:50]}... (ERROR: {error_msg[:100]})")
            results.append({
                "monitor_id": monitor_id,
                "success": False,
                "error": error_msg
            })
    
    print(f"\n[INFO] Monitor执行完成: 成功 {executed}, 失败 {failed}")
    
    return {
        "executed": executed,
        "failed": failed,
        "results": results
    }


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


def _get_latest_findings_timestamp(client, detector_id: Optional[str] = None) -> tuple[int, int]:
    """
    获取最新findings的时间戳和数量
    返回: (timestamp_ms, count)
    """
    try:
        params = {
            'size': 1,
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
        
        findings = findings_resp.get('findings', [])
        total_findings = findings_resp.get('total_findings', len(findings))
        
        if not findings:
            return (0, total_findings)
        
        latest_finding = findings[0]
        timestamp_value = latest_finding.get('timestamp') or latest_finding.get('@timestamp')
        
        dt = parse_datetime(timestamp_value)
        timestamp_ms = int(dt.timestamp() * 1000) if dt is not None else 0
        
        return (timestamp_ms, total_findings)
    except Exception as e:
        print(f"[WARNING] 查询findings时间戳失败: {e}")
        return (0, 0)


def _get_latest_findings_count(client, detector_id: str) -> int:
    """使用Security Analytics的findings API获取findings数量"""
    try:
        findings_resp = client.transport.perform_request(
            'GET',
            SA_FINDINGS_SEARCH_API,
            params={'detector_id': detector_id, 'size': 0}
        )
        return findings_resp.get('total_findings', 0)
    except Exception:
        return 0


def _filter_new_findings(findings: list[dict[str, Any]], last_timestamp: Optional[datetime]) -> list[dict[str, Any]]:
    """过滤出新的findings（时间戳大于last_timestamp）"""
    if last_timestamp is None:
        return findings

    if last_timestamp.tzinfo is None:
        last_timestamp = last_timestamp.replace(tzinfo=timezone.utc)
    
    new_findings = []
    for finding in findings:
        timestamp_value = finding.get('timestamp') or finding.get('@timestamp')
        if not timestamp_value:
            new_findings.append(finding)
            continue
        
        finding_ts = parse_datetime(timestamp_value)
        if finding_ts is None:
            new_findings.append(finding)
            continue

        if finding_ts > last_timestamp:
            new_findings.append(finding)
    
    return new_findings


def _get_last_processed_timestamp(client, detector_id: str) -> Optional[datetime]:
    """获取上次处理findings的时间戳"""
    try:
        raw_index_name = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], datetime.now(timezone.utc))
        
        if not index_exists(raw_index_name):
            return None
        
        # 使用 client.search() 直接查询，支持完整的查询体（包括 sort）
        query_body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"custom.finding.providers": "security_analytics"}},
                        {"exists": {"field": "@timestamp"}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 1
        }
        
        response = client.search(
            index=raw_index_name,
            body=query_body
        )
        
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            return None
        
        latest = hits[0].get('_source', {})
        timestamp_value = latest.get('@timestamp') or latest.get('event', {}).get('created')
        return parse_datetime(timestamp_value)
    except Exception:
        return None


def _clean_detector_for_update(detector: dict) -> dict:
    """清理detector对象，移除可能导致更新错误的字段"""
    fields_to_remove = [
        'last_update_time', 'created_at', 'updated_at', '@timestamp',
        '_version', '_seq_no', '_primary_term', 'monitor_id', 'detector_id',
    ]
    
    cleaned = detector.copy()
    for field in fields_to_remove:
        cleaned.pop(field, None)
    
    return cleaned


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
    """临时缩短schedule以触发扫描"""
    schedule = detector.get('schedule', {})
    original_schedule = schedule.copy()
    original_interval = schedule.get('period', {}).get('interval', 24)
    original_unit = schedule.get('period', {}).get('unit', 'HOURS')
    
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
    
    if original_unit == 'MINUTES':
        print(f"[INFO] Schedule已较短（{original_interval}分钟），等待自动扫描...")
        return original_schedule, False
    
    return original_schedule, False


def _restore_schedule(client, detector_id: str, original_schedule: dict) -> None:
    """恢复原始schedule"""
    try:
        print(f"[INFO] 准备恢复schedule...")
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
    """轮询确认扫描完成"""
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
        
        if baseline_timestamp_ms > 0:
            current_timestamp_ms, _ = _get_latest_findings_timestamp(client, detector_id)
            if current_timestamp_ms > baseline_timestamp_ms:
                scan_wait_ms = int((time.time() - start_time) * 1000)
                print(f"[INFO] 扫描完成！发现新findings（时间戳: {baseline_timestamp_ms} -> {current_timestamp_ms}）")
                return True, scan_wait_ms
        
        elapsed = int(time.time() - start_time)
        if elapsed % 10 == 0:
            print(f"[INFO] 等待扫描完成... ({elapsed}/{max_wait_seconds}秒)")
    
    scan_wait_ms = int((time.time() - start_time) * 1000)
    print(f"[WARNING] 扫描超时（{scan_wait_ms}ms），可能未完成，但仍会查询findings")
    return False, scan_wait_ms


def _trigger_scan_with_lock(
    client,
    detector_id: str,
    detector: dict,
    baseline_timestamp_ms: int,
    baseline_count: int,
    max_wait_seconds: int
) -> dict[str, Any]:
    """使用锁机制触发扫描"""
    import time
    from .trigger_lock import get_detector_lock, register_trigger, complete_trigger
    
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
            _enable_detector_if_needed(client, detector_id, detector)
            
            original_schedule, schedule_was_shortened = _temporarily_shorten_schedule(
                client, detector_id, detector
            )
            
            if schedule_was_shortened:
                scan_completed, scan_wait_ms = _poll_for_scan_completion(
                    client, detector_id, baseline_timestamp_ms, baseline_count, max_wait_seconds
                )
                source = "triggered_scan_schedule" if scan_completed else "cached_findings"
            else:
                print("[INFO] Detector schedule已较短，等待自动扫描...")
                wait_seconds = max(DEFAULT_POLL_INTERVAL_SECONDS, 30)
                time.sleep(wait_seconds)
                remaining_wait = max_wait_seconds - wait_seconds
                if remaining_wait > 0:
                    scan_completed, scan_wait_ms = _poll_for_scan_completion(
                        client, detector_id, baseline_timestamp_ms, baseline_count, remaining_wait
                    )
                else:
                    scan_completed = False
                    scan_wait_ms = wait_seconds * 1000
                source = "triggered_scan_schedule" if scan_completed else "cached_findings"
        
        return {
            "scan_requested": True,
            "scan_completed": scan_completed,
            "scan_wait_ms": scan_wait_ms,
            "source": source
        }
    
    finally:
        if schedule_was_shortened and original_schedule:
            _restore_schedule(client, detector_id, original_schedule)
        
        complete_trigger(detector_id)


def _fetch_and_store_findings(
    client, 
    detector_id: str, 
    only_new: bool = True,
    time_window_seconds: int = DATA_QUERY_TIME_WINDOW_SECONDS
) -> dict[str, Any]:
    """
    查询findings并存储（支持增量处理）
    
    参数：
    - client: OpenSearch客户端
    - detector_id: Detector ID
    - only_new: 是否只处理新findings
    - time_window_seconds: 查询时间窗口（秒），只查询最近N秒的数据
    """
    from .storage import store_events
    
    # 计算查询时间范围（最近N秒）
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(seconds=time_window_seconds)
    
    last_timestamp = None
    if only_new:
        # 使用时间窗口和上次处理时间中较新的那个
        last_timestamp = _get_last_processed_timestamp(client, detector_id)
        if last_timestamp:
            # 取两者中较新的时间（确保只查询最近的数据）
            if start_time > last_timestamp:
                last_timestamp = start_time
            print(f"[INFO] 查询时间范围: {last_timestamp.isoformat()} 至 {end_time.isoformat()}（最近{time_window_seconds}秒）")
        else:
            last_timestamp = start_time
            print(f"[INFO] 未找到上次处理时间，将查询最近{time_window_seconds}秒的数据")
    else:
        last_timestamp = start_time
        print(f"[INFO] 查询最近{time_window_seconds}秒的数据")
    
    try:
        params = {'size': 1000}
        if detector_id:
            params['detector_id'] = detector_id
        
        findings_resp = client.transport.perform_request(
            'GET',
            SA_FINDINGS_SEARCH_API,
            params=params
        )
        findings = findings_resp.get('findings', [])
        print(f"[INFO] 从Security Analytics API获取到 {len(findings)} 个findings（将过滤为最近{time_window_seconds}秒的数据，从 {last_timestamp.isoformat() if last_timestamp else 'N/A'} 开始）")
        
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


def _check_and_setup_rules_detectors() -> bool:
    """
    检查规则和detector，如果没有则提示用户手动导入和创建
    
    返回：
    - True: 规则和detector已就绪
    - False: 缺少规则或detector
    """
    client = get_client()
    
    try:
        # 1. 检查是否有规则
        rules_resp = client.transport.perform_request(
            'POST',
            SA_RULES_SEARCH_API,
            body={"query": {"match_all": {}}, "size": 1}
        )
        rules_total = rules_resp.get('hits', {}).get('total', {}).get('value', 0)
        
        # 2. 检查是否有detector
        detectors_resp = client.transport.perform_request(
            'POST',
            SA_DETECTORS_SEARCH_API,
            body={"query": {"match_all": {}}, "size": 1}
        )
        detectors_total = detectors_resp.get('hits', {}).get('total', {}).get('value', 0)
        
        # 如果规则和detector都存在，直接返回
        if rules_total > 0 and detectors_total > 0:
            print(f"[INFO] 规则和detector已就绪（规则: {rules_total}, Detector: {detectors_total}）")
            return True
        
        # 如果没有规则或detector，提示用户
        print(f"\n[WARNING] 检测到规则或detector缺失:")
        print(f"  规则数量: {rules_total}")
        print(f"  Detector数量: {detectors_total}")
        
        if rules_total == 0:
            print(f"\n[INFO] 未找到规则（预打包规则应该已经内置在OpenSearch中）")
            print(f"[INFO] 如果确实没有规则，请检查:")
            print(f"  1. OpenSearch Security Analytics 插件是否正确安装")
            print(f"  2. 是否需要重启 OpenSearch 服务")
            print(f"  3. 可以运行以下命令检查预打包规则:")
            print(f"     cd backend/app/services/opensearch/scripts")
            print(f"     uv run python import_sigma_rules.py --auto")
        
        if detectors_total == 0:
            print(f"\n[INFO] 需要创建detector，请运行:")
            print(f"  cd backend/app/services/opensearch/scripts")
            print(f"  uv run python setup_security_analytics.py --multiple")
        
        # 尝试自动调用脚本（如果scripts目录存在）
        import sys
        import os
        import subprocess
        from pathlib import Path
        
        scripts_dir = Path(__file__).parent / "scripts"
        if scripts_dir.exists():
            print(f"\n[INFO] 尝试检查预打包规则和创建detector...")
            
            try:
                # 如果没有规则，检查预打包规则
                if rules_total == 0:
                    print("[INFO] 检查OpenSearch Security Analytics预打包规则...")
                    try:
                        prepackaged_resp = client.transport.perform_request(
                            'POST',
                            SA_RULES_SEARCH_API,
                            body={
                                "query": {"match_all": {}},
                                "size": 1
                            }
                        )
                        prepackaged_total = prepackaged_resp.get('hits', {}).get('total', {}).get('value', 0)
                        
                        if prepackaged_total > 0:
                            print(f"[OK] 发现 {prepackaged_total} 个预打包规则（已内置，无需导入）")
                        else:
                            print("[WARNING] 未找到预打包规则")
                            print("[INFO] OpenSearch Security Analytics可能未正确安装或配置")
                    except Exception as e:
                        print(f"[WARNING] 检查预打包规则失败: {e}")
                        print("[INFO] 预打包规则应该已经内置在OpenSearch中，如果缺失可能是安装问题")
                
                # 如果没有detector，创建detector
                if detectors_total == 0:
                    print("[INFO] 正在创建detector...")
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    result = subprocess.run(
                        [sys.executable, str(scripts_dir / "setup_security_analytics.py"), "--multiple"],
                        cwd=str(scripts_dir),
                        capture_output=False,
                        timeout=300,
                        env=env
                    )
                    if result.returncode == 0:
                        print("[OK] Detector创建成功")
                    else:
                        print("[WARNING] Detector创建可能失败，请检查输出")
                
                # 再次检查
                rules_resp = client.transport.perform_request(
                    'POST',
                    SA_RULES_SEARCH_API,
                    body={"query": {"match_all": {}}, "size": 1}
                )
                rules_total_after = rules_resp.get('hits', {}).get('total', {}).get('value', 0)
                
                detectors_resp = client.transport.perform_request(
                    'POST',
                    SA_DETECTORS_SEARCH_API,
                    body={"query": {"match_all": {}}, "size": 1}
                )
                detectors_total_after = detectors_resp.get('hits', {}).get('total', {}).get('value', 0)
                
                if rules_total_after > 0 and detectors_total_after > 0:
                    print(f"[OK] 规则和detector设置完成（规则: {rules_total_after}, Detector: {detectors_total_after}）")
                    return True
                else:
                    print(f"[WARNING] 自动设置后仍缺少规则或detector")
                    return False
                    
            except subprocess.TimeoutExpired:
                print(f"[WARNING] 自动设置超时，请手动运行上述命令")
                return False
            except Exception as e:
                print(f"[WARNING] 自动设置失败: {e}")
                print(f"[WARNING] 请手动运行上述命令")
                return False
        else:
            return False
            
    except Exception as e:
        print(f"[WARNING] 检查规则和detector失败: {e}")
        return False


def run_security_analytics(
    trigger_scan: bool = True,
    max_wait_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    force_scan: bool = False,
) -> dict[str, Any]:
    """
    运行 OpenSearch Security Analytics 检测并读取结果写入 raw-findings-*
    
    新策略：
    1. **从 .opensearch-sap-detectors-config 索引获取所有 monitor IDs**
    2. **直接执行 monitors**（使用 /_plugins/_alerting/monitors/{monitor_id}/_execute）
    3. **等待扫描完成**（轮询确认）
    4. **查询并存储findings**（增量处理）
    
    参数：
    - trigger_scan: 是否允许触发新扫描（默认True）
    - max_wait_seconds: 触发扫描后的最大等待时间（默认60秒）
    - force_scan: 是否强制触发一次扫描（默认False）
    
    返回：
    - success: 是否成功
    - findings_count: 查询到的findings总数（所有detector汇总）
    - new_findings_count: 新的findings数量（已过滤重复）
    - stored: 存储成功的数量
    - scan_requested: 是否请求了新扫描
    - scan_completed: 扫描是否完成
    - scan_wait_ms: 实际等待时间（毫秒）
    - source: "triggered_monitor_execute" | "cached_findings" | "no_findings"
    """
    import time
    
    client = get_client()
    
    try:
        # 步骤1: 获取所有 monitor IDs
        monitor_ids = _get_all_monitor_ids(client, enabled_only=True)
        
        if not monitor_ids:
            print("[WARNING] 未找到任何 monitor IDs")
            print("[INFO] 将跳过触发扫描，直接查询已有findings")
            monitor_ids = []
        
        # 步骤2: 查询已有findings的时间戳和数量（汇总所有detector）
        all_detector_ids = []
        total_baseline_count = 0
        
        # 获取所有detector IDs
        try:
            detectors_resp = client.transport.perform_request(
                'POST',
                SA_DETECTORS_SEARCH_API,
                body={"query": {"match_all": {}}, "size": 1000}
            )
            detector_hits = detectors_resp.get('hits', {}).get('hits', [])
            all_detector_ids = [hit.get('_id') for hit in detector_hits if hit.get('_id')]
            
            # 汇总所有detector的findings数量
            for detector_id in all_detector_ids:
                count = _get_latest_findings_count(client, detector_id)
                total_baseline_count += count
        except Exception as e:
            print(f"[WARNING] 查询detector列表失败: {e}")
        
        baseline_timestamp_ms, _ = _get_latest_findings_timestamp(client, detector_id=None)
        findings_age_minutes = None
        
        if total_baseline_count > 0:
            print(f"[INFO] 发现已有findings: {total_baseline_count} 个（来自 {len(all_detector_ids)} 个detector）")
            if baseline_timestamp_ms > 0:
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
            if total_baseline_count == 0:
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
        
        source = "cached_findings" if total_baseline_count > 0 else "no_findings"
        
        # 步骤4: 如果需要触发，执行monitors
        scan_info = {
            "scan_requested": False,
            "scan_completed": False,
            "scan_wait_ms": 0,
            "source": source
        }
        
        if need_trigger:
            if monitor_ids:
                print(f"[INFO] 执行 {len(monitor_ids)} 个 monitors...")
                execute_start_ms = int(time.time() * 1000)
                
                execute_result = _execute_monitors(client, monitor_ids, max_wait_seconds)
                
                execute_end_ms = int(time.time() * 1000)
                scan_wait_ms = execute_end_ms - execute_start_ms
                
                # Monitor执行 = 执行一次Detector扫描（异步）
                # Monitor Execute API调用后，扫描任务被提交并开始执行，但扫描是异步的
                # 需要等待扫描完成并生成findings，我们通过轮询检查findings是否更新来确认扫描完成
                if execute_result['executed'] > 0:
                    print(f"[INFO] Monitor执行成功（扫描已触发），等待扫描完成并生成findings（最多 {max_wait_seconds} 秒，每{DEFAULT_POLL_INTERVAL_SECONDS}秒检查一次）...")
                    wait_start_ms = int(time.time() * 1000)
                    
                    # 轮询确认扫描完成（快速检查，不需要等待1分钟）
                    poll_interval = DEFAULT_POLL_INTERVAL_SECONDS  # 1秒检查一次
                    max_poll_time = max_wait_seconds  # 最多等待10秒
                    poll_start = time.time()
                    
                    scan_completed = False
                    check_count = 0
                    while (time.time() - poll_start) < max_poll_time:
                        check_count += 1
                        # 检查是否有新findings
                        current_timestamp_ms, current_count = _get_latest_findings_timestamp(client, detector_id=None)
                        
                        if current_count > total_baseline_count or (current_timestamp_ms > baseline_timestamp_ms and baseline_timestamp_ms > 0):
                            scan_completed = True
                            elapsed = int(time.time() - poll_start)
                            print(f"[INFO] 检测到新findings，扫描已完成（第{check_count}次检查，耗时{elapsed}秒）")
                            break
                        
                        # 每5次检查打印一次进度（避免日志过多）
                        if check_count % 5 == 0:
                            elapsed = int(time.time() - poll_start)
                            print(f"[INFO] 等待扫描完成... ({elapsed}/{max_poll_time}秒，已检查{check_count}次)")
                        
                        time.sleep(poll_interval)
                    
                    if not scan_completed:
                        elapsed = int(time.time() - poll_start)
                        print(f"[WARNING] 扫描未在{max_poll_time}秒内完成（已等待{elapsed}秒），将使用已有findings")
                    
                    wait_end_ms = int(time.time() * 1000)
                    scan_wait_ms += (wait_end_ms - wait_start_ms)
                    
                    scan_info = {
                        "scan_requested": True,
                        "scan_completed": scan_completed,
                        "scan_wait_ms": scan_wait_ms,
                        "source": "triggered_monitor_execute"
                    }
                else:
                    scan_info = {
                        "scan_requested": True,
                        "scan_completed": False,
                        "scan_wait_ms": scan_wait_ms,
                        "source": "triggered_monitor_execute"
                    }
            else:
                print("[WARNING] 需要触发扫描但没有 monitor IDs，无法执行")
                print("[INFO] 将直接查询已有findings")
                scan_info = {
                    "scan_requested": False,
                    "scan_completed": False,
                    "scan_wait_ms": 0,
                    "source": "cached_findings"
                }
        
        # 步骤5: 查询并存储findings（汇总所有detector）
        total_findings_count = 0
        total_new_findings_count = 0
        total_stored = 0
        total_failed = 0
        total_duplicated = 0
        
        for detector_id in all_detector_ids:
            storage_result = _fetch_and_store_findings(
                client, 
                detector_id, 
                only_new=True,
                time_window_seconds=DATA_QUERY_TIME_WINDOW_SECONDS
            )
            total_findings_count += storage_result.get("findings_count", 0)
            total_new_findings_count += storage_result.get("new_findings_count", 0)
            total_stored += storage_result.get("stored", 0)
            total_failed += storage_result.get("failed", 0)
            total_duplicated += storage_result.get("duplicated", 0)
        
        return {
            "success": True,
            "message": f"成功处理 {len(all_detector_ids)} 个detector的findings",
            "findings_count": total_findings_count,
            "new_findings_count": total_new_findings_count,
            "stored": total_stored,
            "failed": total_failed,
            "duplicated": total_duplicated,
            **scan_info
        }
    
    except Exception as error:
        error_msg = str(error)
        print(f"[ERROR] Security Analytics检测失败: {error_msg}")
        return {
            "success": False,
            "message": error_msg,
            "findings_count": 0,
            "new_findings_count": 0,
            "stored": 0,
            "failed": 0,
            "duplicated": 0,
            "scan_requested": False,
            "scan_completed": False,
            "scan_wait_ms": 0,
            "source": "no_findings"
        }


# ========== Correlation Rules 管理 ==========

def _ensure_http_line_length_setting(client: Any, length: str = "16kb") -> None:
    """
    确保 OpenSearch HTTP 行长度限制设置足够大
    
    这个函数会在查询 correlation 之前自动调用，确保不会因为 URL 过长而报错。
    
    参数：
    - client: OpenSearch 客户端
    - length: HTTP 行长度限制（默认 16kb）
    """
    try:
        # 检查当前设置
        response = client.cluster.get_settings(
            include_defaults=False,
            filter_path="*.http.max_initial_line_length"
        )
        
        # 提取当前值
        persistent = response.get("persistent", {}).get("network", {}).get("http", {}).get("max_initial_line_length")
        transient = response.get("transient", {}).get("network", {}).get("http", {}).get("max_initial_line_length")
        current = transient or persistent
        
        # 如果当前值小于目标值，则设置
        if not current or _parse_size(current) < _parse_size(length):
            try:
                client.cluster.put_settings(
                    body={
                        "persistent": {
                            "http.max_initial_line_length": length
                        }
                    }
                )
                print(f"[INFO] 已设置 http.max_initial_line_length = {length}（避免 URL 过长错误）")
            except Exception as e:
                # 如果 persistent 失败，尝试 transient
                try:
                    client.cluster.put_settings(
                        body={
                            "transient": {
                                "http.max_initial_line_length": length
                            }
                        }
                    )
                    print(f"[INFO] 已设置 http.max_initial_line_length = {length}（transient，避免 URL 过长错误）")
                except Exception as e2:
                    print(f"[WARNING] 无法设置 http.max_initial_line_length: {e2}")
    except Exception as e:
        # 如果查询设置失败，尝试直接设置
        try:
            client.cluster.put_settings(
                body={
                    "persistent": {
                        "http.max_initial_line_length": length
                    }
                }
            )
            print(f"[INFO] 已设置 http.max_initial_line_length = {length}")
        except Exception as e2:
            print(f"[WARNING] 设置 http.max_initial_line_length 失败: {e2}")


def _parse_size(size_str: str) -> int:
    """
    解析大小字符串（如 "16kb", "4kb"）为字节数
    
    参数：
    - size_str: 大小字符串，如 "16kb", "4kb", "16384b" 等
    
    返回: 字节数
    """
    size_str = size_str.lower().strip()
    
    if size_str.endswith("kb"):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith("mb"):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith("b"):
        return int(size_str[:-1])
    else:
        # 假设是字节数
        return int(size_str)


def create_lateral_movement_correlation_rule(
    rule_name: str = "Lateral Movement Detection",
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES,
    enabled: bool = True
) -> dict[str, Any]:
    """
    创建横向移动检测的 Correlation Rule
    
    规则逻辑：
    1. Query1: 主机A上的提权行为（Privilege Escalation）
    2. Query2: 从A到B的远程连接/登录（Remote Connect/Logon）
    3. Query3: 主机B上的提权或远程执行行为（Privilege Escalation / Remote Execution）
    
    参数：
    - rule_name: 规则名称
    - time_window_minutes: 关联时间窗口（分钟）
    - enabled: 是否启用
    
    返回: {
        "success": bool,
        "rule_id": str,
        "message": str
    }
    """
    client = get_client()
    
    # 获取 events 索引模式（correlation rules 应该在原始 events 中匹配，不是 findings）
    events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    # ========== 查询条件构建 ==========
    # 
    # 重要说明：根据当前 ECS 规范，单条进程创建 event 无法判断"提权成功"
    # - 当前 ECS events 缺少：process.integrity_level, process.token.elevation, user.effective 等字段
    # - 只能判断"提权尝试"或"可疑提权行为"（基于进程名/命令行特征）
    # - 真正的"提权成功"需要结合后续事件（服务创建、计划任务等）或多事件关联
    #
    # 策略：使用分级判断（方案2：基于父进程特征）
    # - Level 1: 提权尝试（基于进程特征）- 置信度 0.3-0.5
    # - Level 2: 可疑提权行为（提权尝试 + 父进程异常）- 置信度 0.5-0.7
    # - Level 3: 提权成功（提权尝试 + 后续高权限操作）- 置信度 0.8-1.0（需要多事件关联）
    
    # 可疑父进程列表（浏览器、邮件客户端）- Linux/Unix 版本
    # 注意：已移除 Windows 进程名（.exe），只保留 Linux/Unix 进程名
    suspicious_parent_processes = [
        "chrome",           # Chrome 浏览器（Linux）
        "firefox",          # Firefox 浏览器（Linux）
        "chromium",         # Chromium 浏览器（Linux）
        "thunderbird",      # Thunderbird 邮件客户端（Linux）
        "evolution",        # Evolution 邮件客户端（Linux）
        "geary"             # Geary 邮件客户端（Linux）
    ]
    
    # 构建提权检测查询条件（进程特征 + 父进程特征）
    privilege_detection_conditions = [
        "process.name:*privilege*",
        "process.name:*elevate*",
        "process.command_line:*runas*",
        "process.command_line:*sudo*",
        "process.command_line:*su *",
    ] + [f"process.parent.name:{parent}" for parent in suspicious_parent_processes]
    
    privilege_detection_query = " OR ".join(privilege_detection_conditions)
    
    # Query1: 主机A上的提权行为（Privilege Escalation）
    query1 = (
        "event.category:process AND "
        "event.action:process_start AND "
        f"({privilege_detection_query}) AND "
        "_exists_:host.name"
    )
    
    # Query2: 从A到B的远程连接事件（Remote Connect）
    # 注意：排除 HTTP/HTTPS 连接（80, 443），因为横向移动通常不使用 HTTP
    # 横向移动常用的协议和端口：
    # - RDP: 3389
    # - SSH: 22
    # - SMB: 445
    # - WinRM: 5985, 5986
    # - Telnet: 23
    # - VNC: 5900-5909
    # - 其他管理端口
    query2 = (
        "event.category:network AND "
        "_exists_:source.ip AND "
        "_exists_:destination.ip AND "
        "_exists_:host.name AND "
        "network.direction:outbound AND "
        "NOT (destination.port:80 OR destination.port:443 OR destination.port:8080 OR destination.port:8443)"
    )
    
    # Query3: 主机B上的提权或远程执行行为（Privilege Escalation / Remote Execution）
    # 包含进程创建事件（提权尝试）或认证事件（远程登录）
    process_privilege_query = (
        "event.category:process AND "
        "event.action:process_start AND "
        f"({privilege_detection_query})"
    )
    authentication_query = (
        "event.category:authentication AND "
        "event.action:user_login"
    )
    query3 = (
        f"(({process_privilege_query}) OR "
        f"({authentication_query})) AND "
        "_exists_:host.name"
    )
    
    # ========== 构建 Correlation Rule ==========
    correlation_rule = {
        "name": rule_name,
        "description": "检测横向移动攻击链：A主机提权尝试事件 -> A到B远程连接事件 -> B主机提权尝试/远程执行事件",
        "tags": ["attack.lateral_movement", "attack.t1021"],
        "correlate": [
            {
                "index": events_index_pattern,
                "category": "process",  # 改为process，不限制为windows
                "query": query1
            },
            {
                "index": events_index_pattern,
                "category": "network",
                "query": query2
            },
            {
                "index": events_index_pattern,
                "category": "process",  # 改为process，不限制为windows
                "query": query3
            }
        ]
    }
    
    return _create_or_update_correlation_rule(client, correlation_rule, rule_name)


def create_port_scanning_correlation_rule(
    rule_name: str = "Port Scanning Detection",
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES,
    enabled: bool = True
) -> dict[str, Any]:
    """
    创建端口扫描检测的 Correlation Rule
    
    规则逻辑：
    1. Query1: 短时间内从同一源IP到同一目标IP的多个端口连接尝试（扫描行为）
    2. Query2: 扫描后的成功连接建立
    3. Query3: 连接后的异常行为（文件访问、命令执行等）
    
    参数：
    - rule_name: 规则名称
    - time_window_minutes: 关联时间窗口（分钟）
    - enabled: 是否启用
    
    返回: {
        "success": bool,
        "rule_id": str,
        "message": str
    }
    """
    client = get_client()
    events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    # Query1: 端口扫描行为 - 短时间内访问多个不同端口
    # 注意：实际扫描检测需要聚合查询，这里使用网络连接事件作为基础
    query1 = (
        "event.category:network AND "
        "event.type:connection AND "
        "_exists_:source.ip AND "
        "_exists_:destination.ip AND "
        "_exists_:destination.port AND "
        "network.direction:outbound AND "
        "(tags:attack.discovery OR tags:attack.t1046 OR tags:attack.t1040)"
    )
    
    # Query2: 扫描后的成功连接（建立会话）
    query2 = (
        "event.category:network AND "
        "event.type:connection AND "
        "event.action:network_connection_established AND "
        "_exists_:source.ip AND "
        "_exists_:destination.ip"
    )
    
    # Query3: 连接后的异常行为（文件访问、命令执行、数据访问）
    query3 = (
        "(event.category:file AND event.action:file_read) OR "
        "(event.category:process AND event.action:process_start) OR "
        "(event.category:network AND event.action:network_flow_end AND network.bytes > 100000)"
    )
    
    correlation_rule = {
        "name": rule_name,
        "description": "检测端口扫描攻击链：端口扫描尝试 -> 成功连接建立 -> 后续异常行为",
        "tags": ["attack.discovery", "attack.t1046", "attack.t1040"],
        "correlate": [
            {
                "index": events_index_pattern,
                "category": "network",
                "query": query1
            },
            {
                "index": events_index_pattern,
                "category": "network",
                "query": query2
            },
            {
                "index": events_index_pattern,
                "category": "network",
                "query": query3
            }
        ]
    }
    
    return _create_or_update_correlation_rule(client, correlation_rule, rule_name)


def create_privilege_escalation_correlation_rule(
    rule_name: str = "Privilege Escalation Detection",
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES,
    enabled: bool = True
) -> dict[str, Any]:
    """
    创建权限提升检测的 Correlation Rule
    
    规则逻辑：
    1. Query1: 可疑的提权尝试（sudo、runas、UAC等）
    2. Query2: 提权后的高权限操作（系统文件访问、服务创建等）
    3. Query3: 权限滥用行为（敏感目录访问、注册表修改等）
    
    参数：
    - rule_name: 规则名称
    - time_window_minutes: 关联时间窗口（分钟）
    - enabled: 是否启用
    
    返回: {
        "success": bool,
        "rule_id": str,
        "message": str
    }
    """
    client = get_client()
    events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    # 可疑提权命令和进程
    privilege_keywords = [
        "*sudo*", "*runas*", "*elevate*", "*privilege*",
        "*UAC*", "*gksu*", "*pkexec*", "*su *"
    ]
    
    privilege_query = " OR ".join([f"process.command_line:{kw}" for kw in privilege_keywords])
    
    # Query1: 提权尝试
    query1 = (
        "event.category:process AND "
        "event.action:process_start AND "
        f"({privilege_query} OR tags:attack.privilege_escalation OR tags:attack.t1078 OR tags:attack.t1548) AND "
        "_exists_:host.name"
    )
    
    # Query2: 提权后的高权限操作（移除Windows特定路径）
    query2 = (
        "(event.category:file AND event.action:file_access AND "
        "(file.path:/etc/* OR file.path:/usr/bin/* OR file.path:/usr/sbin/*)) OR "
        "(event.category:process AND event.action:process_start AND "
        "(process.name:*service* OR process.name:*systemd*))"
    )
    
    # Query3: 权限滥用行为（移除Windows注册表和Windows路径）
    query3 = (
        "(event.category:file AND event.action:file_modify AND "
        "(file.path:/etc/passwd OR file.path:/etc/shadow OR file.path:/etc/sudoers)) OR "
        "(event.category:process AND event.action:process_start AND "
        "(process.command_line:*chmod* OR process.command_line:*chown* OR process.command_line:*sudo*))"
    )
    
    correlation_rule = {
        "name": rule_name,
        "description": "检测权限提升攻击链：提权尝试 -> 高权限操作 -> 权限滥用行为",
        "tags": ["attack.privilege_escalation", "attack.t1078", "attack.t1548"],
        "correlate": [
            {
                "index": events_index_pattern,
                "category": "process",
                "query": query1
            },
            {
                "index": events_index_pattern,
                "category": "file",
                "query": query2
            },
            {
                "index": events_index_pattern,
                "category": "process",
                "query": query3
            }
        ]
    }
    
    return _create_or_update_correlation_rule(client, correlation_rule, rule_name)


def create_data_exfiltration_correlation_rule(
    rule_name: str = "Data Exfiltration Detection",
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES,
    enabled: bool = True
) -> dict[str, Any]:
    """
    创建数据泄露检测的 Correlation Rule
    
    规则逻辑：
    1. Query1: 大量数据传输（大文件读取、批量文件访问）
    2. Query2: 异常网络连接（到外部IP、非标准端口）
    3. Query3: 数据传输完成（大流量网络事件）
    
    参数：
    - rule_name: 规则名称
    - time_window_minutes: 关联时间窗口（分钟）
    - enabled: 是否启用
    
    返回: {
        "success": bool,
        "rule_id": str,
        "message": str
    }
    """
    client = get_client()
    events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    # Query1: 大量数据传输准备（文件读取、压缩、打包）
    query1 = (
        "(event.category:file AND event.action:file_read AND file.size:>1000000) OR "
        "(event.category:process AND event.action:process_start AND "
        "(process.command_line:*tar* OR process.command_line:*zip* OR process.command_line:*7z* OR "
        "process.command_line:*rar* OR process.command_line:*compress*)) OR "
        "tags:attack.collection OR tags:attack.t1005 OR tags:attack.t1074"
    )
    
    # Query2: 异常网络连接（到外部IP、非标准端口）
    query2 = (
        "event.category:network AND "
        "event.type:connection AND "
        "_exists_:destination.ip AND "
        "network.direction:outbound AND "
        "(NOT destination.ip:10.* AND NOT destination.ip:172.16.* AND NOT destination.ip:192.168.*) AND "
        "(destination.port:>1024 OR destination.port:443 OR destination.port:80)"
    )
    
    # Query3: 大流量数据传输
    query3 = (
        "event.category:network AND "
        "(event.action:network_flow_end OR event.type:flow) AND "
        "network.bytes:>10000000 AND "
        "network.direction:outbound"
    )
    
    correlation_rule = {
        "name": rule_name,
        "description": "检测数据泄露攻击链：大量数据准备 -> 异常网络连接 -> 大流量传输",
        "tags": ["attack.exfiltration", "attack.t1041", "attack.t1048"],
        "correlate": [
            {
                "index": events_index_pattern,
                "category": "file",
                "query": query1
            },
            {
                "index": events_index_pattern,
                "category": "network",
                "query": query2
            },
            {
                "index": events_index_pattern,
                "category": "network",
                "query": query3
            }
        ]
    }
    
    return _create_or_update_correlation_rule(client, correlation_rule, rule_name)


def create_persistence_correlation_rule(
    rule_name: str = "Persistence Detection",
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES,
    enabled: bool = True
) -> dict[str, Any]:
    """
    创建持久化攻击检测的 Correlation Rule
    
    规则逻辑：
    1. Query1: 服务/计划任务创建（持久化机制建立）
    2. Query2: 启动项修改（Linux/Unix持久化）
    3. Query3: 持久化后的异常执行（定时任务触发、服务启动等）
    
    参数：
    - rule_name: 规则名称
    - time_window_minutes: 关联时间窗口（分钟）
    - enabled: 是否启用
    
    返回: {
        "success": bool,
        "rule_id": str,
        "message": str
    }
    """
    client = get_client()
    events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    # Query1: 服务/计划任务创建（移除Windows注册表相关）
    query1 = (
        "(event.category:process AND event.action:process_start AND "
        "(process.command_line:*crontab* OR process.command_line:*systemctl* OR "
        "process.command_line:*service* OR process.command_line:*at *)) OR "
        "tags:attack.persistence OR tags:attack.t1543 OR tags:attack.t1547"
    )
    
    # Query2: 启动项修改（只保留Linux/Unix启动项，移除Windows路径避免查询解析错误）
    query2 = (
        "(event.category:file AND event.action:file_create AND "
        "(file.path:*rc.local* OR file.path:*/.config/autostart* OR "
        "file.path:/etc/systemd/system/*.service OR file.path:/etc/init.d/*))"
    )
    
    # Query3: 持久化后的异常执行（移除Windows特定进程）
    query3 = (
        "(event.category:process AND event.action:process_start AND "
        "process.parent.name:(*cron* OR *systemd*)) OR "
        "(event.category:authentication AND event.action:user_login AND "
        "event.outcome:success)"
    )
    
    correlation_rule = {
        "name": rule_name,
        "description": "检测持久化攻击链：服务/任务创建 -> 启动项修改 -> 异常执行",
        "tags": ["attack.persistence", "attack.t1543", "attack.t1547"],
        "correlate": [
            {
                "index": events_index_pattern,
                "category": "process",
                "query": query1
            },
            {
                "index": events_index_pattern,
                "category": "registry",
                "query": query2
            },
            {
                "index": events_index_pattern,
                "category": "process",
                "query": query3
            }
        ]
    }
    
    return _create_or_update_correlation_rule(client, correlation_rule, rule_name)


def _create_or_update_correlation_rule(
    client: Any,
    correlation_rule: dict[str, Any],
    rule_name: str
) -> dict[str, Any]:
    """
    通用的创建或更新 Correlation Rule 的辅助函数
    
    参数：
    - client: OpenSearch客户端
    - correlation_rule: 规则定义
    - rule_name: 规则名称（用于去重检查）
    
    返回: {
        "success": bool,
        "rule_id": str,
        "message": str
    }
    """
    try:
        # Step 1: 查询是否存在同名规则
        rule_id = None
        try:
            search_response = client.transport.perform_request(
                'POST',
                f"{CORRELATION_RULES_API}/_search",
                body={
                    "query": {
                        "match": {
                            "name": rule_name
                        }
                    },
                    "size": 10
                }
            )
            
            if isinstance(search_response, dict):
                hits = search_response.get("hits", {}).get("hits", [])
                for hit in hits:
                    rule_source = hit.get("_source", {})
                    if rule_source.get("name") == rule_name:
                        rule_id = hit.get("_id")
                        print(f"[INFO] 找到已存在的 Correlation Rule (ID: {rule_id})，将更新而不是创建新规则")
                        break
        except Exception as search_error:
            print(f"[WARNING] 查询现有规则失败（将尝试创建新规则）: {search_error}")
        
        # Step 2: 如果存在同名规则，则更新；否则创建新规则
        if rule_id:
            try:
                update_response = client.transport.perform_request(
                    'PUT',
                    f"{CORRELATION_RULES_API}/{rule_id}",
                    body=correlation_rule
                )
                print(f"[INFO] Correlation Rule 更新成功 (ID: {rule_id})")
                return {
                    "success": True,
                    "rule_id": rule_id,
                    "message": "规则更新成功（已去重）"
                }
            except Exception as update_error:
                print(f"[WARNING] 更新规则失败: {update_error}，尝试创建新规则...")
                rule_id = None
        
        # Step 3: 创建新规则
        if not rule_id:
            try:
                create_response = client.transport.perform_request(
                    'POST',
                    CORRELATION_RULES_API,
                    body=correlation_rule
                )
                
                rule_id = None
                if isinstance(create_response, dict):
                    rule_id = create_response.get('_id') or create_response.get('id') or create_response.get('rule_id')
                elif isinstance(create_response, str):
                    rule_id = create_response
                
                if rule_id:
                    print(f"[INFO] Correlation Rule 创建成功 (ID: {rule_id})")
                    return {
                        "success": True,
                        "rule_id": rule_id,
                        "message": "规则创建成功"
                    }
                else:
                    print(f"[WARNING] 创建成功但无法提取 rule_id: {create_response}")
                    return {
                        "success": True,
                        "rule_id": None,
                        "message": "规则创建成功（但无法获取 rule_id）"
                    }
            except Exception as create_error:
                error_msg = str(create_error)
                print(f"[ERROR] 创建 Correlation Rule 失败: {error_msg}")
                raise create_error
        
        return {
            "success": True,
            "rule_id": rule_id,
            "message": "规则创建成功"
        }
        
    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] 创建 Correlation Rule 失败: {error_msg}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "rule_id": None,
            "message": f"创建失败: {error_msg}"
        }


def create_all_correlation_rules(
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES
) -> dict[str, Any]:
    """
    批量创建所有预定义的 Correlation Rules（仅保留最重要的规则）
    
    重要规则列表：
    1. Lateral Movement Detection（横向移动）- 必须保留，绝对不能改
    2. Privilege Escalation Detection（权限提升）- 重要
    3. Data Exfiltration Detection（数据泄露）- 重要
    
    已移除的规则：
    - Port Scanning Detection（端口扫描）- 相对不重要
    - Persistence Detection（持久化）- 相对不重要
    
    参数：
    - time_window_minutes: 关联时间窗口（分钟）
    
    返回: {
        "success": bool,
        "rules_created": List[dict],  # 每个规则创建结果
        "total": int,
        "successful": int,
        "failed": int
    }
    """
    # 只保留最重要的规则
    rules_to_create = [
        {
            "name": "Lateral Movement Detection",
            "func": create_lateral_movement_correlation_rule,
            "params": {"time_window_minutes": time_window_minutes}
        },
        {
            "name": "Privilege Escalation Detection",
            "func": create_privilege_escalation_correlation_rule,
            "params": {"time_window_minutes": time_window_minutes}
        },
        {
            "name": "Data Exfiltration Detection",
            "func": create_data_exfiltration_correlation_rule,
            "params": {"time_window_minutes": time_window_minutes}
        }
    ]
    
    results = []
    successful = 0
    failed = 0
    
    print(f"[INFO] 开始创建 {len(rules_to_create)} 个 Correlation Rules...")
    
    for rule_config in rules_to_create:
        rule_name = rule_config["name"]
        rule_func = rule_config["func"]
        rule_params = rule_config["params"]
        
        print(f"\n[INFO] 创建规则: {rule_name}")
        try:
            result = rule_func(**rule_params)
            results.append({
                "name": rule_name,
                "success": result.get("success", False),
                "rule_id": result.get("rule_id"),
                "message": result.get("message", "")
            })
            
            if result.get("success"):
                successful += 1
                print(f"[OK] {rule_name} 创建成功 (ID: {result.get('rule_id', 'N/A')})")
            else:
                failed += 1
                print(f"[ERROR] {rule_name} 创建失败: {result.get('message', '')}")
        except Exception as e:
            failed += 1
            error_msg = str(e)
            print(f"[ERROR] {rule_name} 创建异常: {error_msg}")
            results.append({
                "name": rule_name,
                "success": False,
                "rule_id": None,
                "message": f"异常: {error_msg}"
            })
    
    print(f"\n[INFO] Correlation Rules 创建完成:")
    print(f"  - 总计: {len(rules_to_create)}")
    print(f"  - 成功: {successful}")
    print(f"  - 失败: {failed}")
    
    return {
        "success": failed == 0,
        "rules_created": results,
        "total": len(rules_to_create),
        "successful": successful,
        "failed": failed
    }


def apply_correlation_rule_manually(
    rule: Dict[str, Any],
    start_time: datetime,
    end_time: datetime,
    events_index_pattern: str = None
) -> List[Dict[str, Any]]:
    """
    手动应用 Correlation Rule（如果 OpenSearch 不支持自动触发）
    
    实现逻辑：
    1. 对 rule 中的每个 correlate 查询，在 events 索引中执行查询
    2. 对每个匹配的 event，进行分级判断（Level 1/2）
    3. 根据时间窗口和关联条件，将多个查询的结果关联起来
    4. 返回关联结果（包含关联的 events 和分级信息）
    
    参数：
    - rule: Correlation Rule 定义
    - start_time: 开始时间
    - end_time: 结束时间
    - events_index_pattern: Events 索引模式（默认：ecs-events-*）
    
    返回: List[correlation_result] 每个结果包含关联的 events 和分级信息
    """
    if events_index_pattern is None:
        events_index_pattern = f"{INDEX_PATTERNS['ECS_EVENTS']}-*"
    
    client = get_client()
    correlate_queries = rule.get('correlate', [])
    
    if len(correlate_queries) < 2:
        return []
    
    # Step 1: 对每个查询执行搜索，获取 events（不是 findings）
    query_results = []
    for i, correlate_query in enumerate(correlate_queries):
        query_string = correlate_query.get('query', '')  # query string 格式
        index = correlate_query.get('index', events_index_pattern)
        
        print(f"[DEBUG] Query {i+1} 查询条件: {query_string}")
        print(f"[DEBUG] Query {i+1} 索引模式: {index}")
        print(f"[DEBUG] Query {i+1} 时间范围: {to_rfc3339(start_time)} 到 {to_rfc3339(end_time)}")
        
        # 将 query string 转换为 DSL query（添加时间范围）
        # 重要：event.category 是数组字段 ['process']，query_string 无法正确匹配数组字段
        # 解决方案：将 query_string 转换为 DSL 查询，使用 term 查询匹配数组字段
        
        # 转义查询字符串中的特殊字符（避免解析错误）
        escaped_query = query_string.replace('\\', '/')  # 将反斜杠替换为正斜杠（统一路径格式）
        
        # 修复数组字段匹配问题：
        # 将 event.category:xxx 替换为 event.category.keyword:xxx（用于匹配数组字段）
        fixed_query = escaped_query.replace('event.category:', 'event.category.keyword:')
        fixed_query = fixed_query.replace('event.type:', 'event.type.keyword:')
        
        # 使用 query_string 查询，但添加 lenient=True 和 default_field 设置
        # 如果 query_string 仍然无法匹配，可以考虑完全改用 DSL 查询
        dsl_query = {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": fixed_query,
                            "default_operator": "AND",
                            "analyze_wildcard": True,
                            "lenient": True,  # 允许部分字段不存在，避免查询失败
                            "default_field": "*"  # 默认在所有字段中搜索
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_rfc3339(start_time),
                                "lte": to_rfc3339(end_time)
                            }
                        }
                    }
                ]
            }
        }
        
        try:
            response = client.search(
                index=index,
                body={
                    "query": dsl_query,
                    "size": 1000  # 获取足够多的结果
                }
            )
            
            total_hits = response.get('hits', {}).get('total', {})
            if isinstance(total_hits, dict):
                total_count = total_hits.get('value', 0)
            else:
                total_count = total_hits
            
            hits = response.get('hits', {}).get('hits', [])
            events = []
            missing_host_name_count = 0
            for hit in hits:
                event_source = hit.get('_source', {})
                
                # 检查是否有 host.name 字段
                host_name = event_source.get('host', {}).get('name')
                if not host_name:
                    missing_host_name_count += 1
                
                # 对每个 event 进行分级判断（如果是提权相关事件）
                level, confidence = classify_privilege_escalation_level(event_source)
                
                events.append({
                    "id": hit.get('_id'),
                    "_id": hit.get('_id'),
                    "event": event_source,  # 注意：这里存储的是 event，不是 finding
                    "privilege_level": level,  # 提权级别（0=不是提权，1=尝试，2=可疑，3=成功）
                    "privilege_confidence": confidence  # 提权置信度
                })
            
            query_results.append({
                "query_index": i,
                "events": events  # 改为 events
            })
            
            # 统计分级结果
            level_counts = {}
            for e in events:
                level = e.get('privilege_level', 0)
                level_counts[level] = level_counts.get(level, 0) + 1
            
            print(f"[DEBUG] Query {i+1} 总命中数: {total_count}, 返回事件数: {len(events)}")
            if missing_host_name_count > 0:
                print(f"[DEBUG] Query {i+1} 警告: {missing_host_name_count} 个事件缺少 host.name 字段")
            if level_counts:
                level_str = ", ".join([f"Level {k}: {v}" for k, v in sorted(level_counts.items()) if k > 0])
                if level_str:
                    print(f"[DEBUG]   分级统计: {level_str}")
            
        except Exception as e:
            print(f"[WARNING] 执行查询 {i+1} 失败: {e}")
            import traceback
            traceback.print_exc()
            query_results.append({
                "query_index": i,
                "events": []
            })
    
    # Step 2: 应用关联逻辑（基于字段匹配和时间窗口）
    # 简化实现：查找满足以下条件的 events 组合：
    # - 来自不同的查询（query_index）
    # - 在时间窗口内
    # - 有可关联的字段（host.name, source.ip, destination.ip, user.name）
    
    correlations = []
    
    # 如果只有2个查询，进行简单的两两关联
    if len(query_results) == 2:
        events_1 = query_results[0].get('events', [])
        events_2 = query_results[1].get('events', [])
        
        for e1 in events_1:
            event_1 = e1.get('event', {})
            host_1 = event_1.get('host', {}).get('id')
            src_ip_1 = event_1.get('source', {}).get('ip')
            dst_ip_1 = event_1.get('destination', {}).get('ip')
            user_1 = event_1.get('user', {}).get('name')
            
            for e2 in events_2:
                event_2 = e2.get('event', {})
                host_2 = event_2.get('host', {}).get('id')
                src_ip_2 = event_2.get('source', {}).get('ip')
                dst_ip_2 = event_2.get('destination', {}).get('ip')
                user_2 = event_2.get('user', {}).get('name')
                
                # 关联条件：
                # 1. 主机不同（跨主机）
                # 2. IP 匹配（src_ip_1 == dst_ip_2 或 dst_ip_1 == src_ip_2）
                # 3. 用户相同（可选）
                
                is_correlated = False
                
                # 条件1: 主机不同
                if host_1 and host_2 and host_1 != host_2:
                    # 条件2: IP 匹配（A的dst_ip == B的src_ip，表示A连接到B）
                    if dst_ip_1 and src_ip_2 and dst_ip_1 == src_ip_2:
                        is_correlated = True
                    elif src_ip_1 and dst_ip_2 and src_ip_1 == dst_ip_2:
                        is_correlated = True
                    
                    # 条件3: 用户相同（增强关联性）
                    if is_correlated and user_1 and user_2 and user_1 == user_2:
                        is_correlated = True
                
                if is_correlated:
                    # 构建 correlation_id（避免嵌套 f-string）
                    corr_key = f"{e1.get('id', '')}-{e2.get('id', '')}"
                    corr_id = f"corr-{hashlib.md5(corr_key.encode()).hexdigest()[:16]}"
                    
                    # 计算综合置信度（基于分级判断）
                    level_1 = e1.get('privilege_level', 0)
                    level_2 = e2.get('privilege_level', 0)
                    conf_1 = e1.get('privilege_confidence', 0.0)
                    conf_2 = e2.get('privilege_confidence', 0.0)
                    
                    # 如果两个事件都是提权相关，使用较高的置信度
                    base_score = 0.8
                    if level_1 > 0 or level_2 > 0:
                        # 提升置信度（基于分级判断）
                        privilege_boost = max(conf_1, conf_2) * 0.2  # 最多提升 0.2
                        base_score = min(base_score + privilege_boost, 1.0)
                    
                    correlations.append({
                        "correlation_id": corr_id,
                        "rule_id": rule.get('name', 'unknown'),
                        "rule_name": rule.get('name', 'unknown'),
                        "timestamp": event_1.get('@timestamp') or event_2.get('@timestamp'),
                        "events": [e1, e2],  # 改为 events
                        "findings": [e1, e2],  # 保持兼容性，但实际是 events
                        "score": base_score,  # 基于分级判断的分数
                        "privilege_levels": [level_1, level_2],  # 记录分级信息
                        "privilege_confidences": [conf_1, conf_2]
                    })
    
    # 如果有3个或更多查询，需要更复杂的关联逻辑
    elif len(query_results) >= 3:
        # 优化实现：使用"最近匹配"策略，避免笛卡尔积
        # 每个Query2事件只匹配时间最近的Query1和Query3事件
        events_1 = query_results[0].get('events', [])
        events_2 = query_results[1].get('events', [])
        events_3 = query_results[2].get('events', [])
        
        # Query1: 主机A上的提权事件（没有网络IP）
        # Query2: 从A到B的网络连接事件（有source.ip和destination.ip）
        # Query3: 主机B上的提权事件（没有网络IP）
        # 
        # 关联策略：对于每个Query2事件，找到时间最近的Query1和Query3事件
        # 1. e1 和 e2：e1在主机A上，e2的源主机也是主机A，且用户相同，时间e1 <= e2
        # 2. e2 和 e3：e2的destination.ip对应主机B，e3在主机B上，且用户相同，时间e2 <= e3
        
        for e2 in events_2:
            event_2 = e2.get('event', {})
            host_2 = event_2.get('host', {}).get('name')
            src_ip_2 = event_2.get('source', {}).get('ip')
            dst_ip_2 = event_2.get('destination', {}).get('ip')
            user_2 = event_2.get('user', {}).get('name')
            timestamp_2 = event_2.get('@timestamp')
            
            if not timestamp_2:
                continue
            
            try:
                ts2 = parse_datetime(timestamp_2)
            except:
                continue
            
            # 为这个Query2事件找到时间最近的Query1事件（在同一主机上，时间 <= e2）
            best_e1 = None
            min_time_diff = None
            
            for e1 in events_1:
                event_1 = e1.get('event', {})
                host_1 = event_1.get('host', {}).get('name')
                user_1 = event_1.get('user', {}).get('name')
                timestamp_1 = event_1.get('@timestamp')
                
                # 检查 e1 和 e2 是否关联：
                # - e1 在主机A上，e2 的源主机也是主机A（host_1 == host_2）
                # - 用户相同（可选，但增强关联性）
                # - 时间顺序：e1 <= e2
                if host_1 and host_2 and host_1 == host_2:
                    # 检查用户匹配
                    user_match = False
                    if user_1 and user_2 and user_1 == user_2:
                        user_match = True
                    elif not user_1 or not user_2:
                        user_match = True  # 用户信息缺失，允许关联
                    
                    if user_match and timestamp_1:
                        try:
                            ts1 = parse_datetime(timestamp_1)
                            if ts1 <= ts2:  # 时间顺序正确
                                time_diff = (ts2 - ts1).total_seconds()
                                if min_time_diff is None or time_diff < min_time_diff:
                                    min_time_diff = time_diff
                                    best_e1 = e1
                        except:
                            pass
            
            if not best_e1:
                continue  # 没有找到匹配的Query1事件
            
            # 为这个Query2事件找到时间最近的Query3事件（在不同主机上，时间 >= e2）
            best_e3 = None
            min_time_diff_3 = None
            
            for e3 in events_3:
                event_3 = e3.get('event', {})
                host_3 = event_3.get('host', {}).get('name')
                host_3_ips = event_3.get('host', {}).get('ip', [])
                # host.ip 可能是字符串或列表
                if isinstance(host_3_ips, str):
                    host_3_ips = [host_3_ips]
                elif not isinstance(host_3_ips, list):
                    host_3_ips = []
                
                user_3 = event_3.get('user', {}).get('name')
                timestamp_3 = event_3.get('@timestamp')
                
                # 检查 e2 和 e3 是否关联：
                # - e2 的 destination.ip 对应主机B（通过 host.ip 验证，如果存在）
                # - e3 在主机B上（host_3）
                # - 用户相同（可选）
                # - 时间顺序：e2 <= e3
                if host_3 and host_2 and host_3 != host_2:
                    # e3 在不同于 e2 源主机的另一台主机上
                    if dst_ip_2:  # e2 有 destination.ip，说明是跨主机连接
                        # 验证 IP 匹配（如果 host.ip 存在）
                        ip_match = True  # 默认匹配（如果 host.ip 不存在，则放宽条件）
                        if host_3_ips and dst_ip_2:
                            # 如果 host.ip 存在，验证 destination.ip 是否在 host.ip 列表中
                            ip_match = dst_ip_2 in host_3_ips
                        
                        if not ip_match:
                            continue  # IP 不匹配，跳过
                        
                        # 检查用户匹配
                        user_match = False
                        if user_2 and user_3 and user_2 == user_3:
                            user_match = True
                        elif not user_2 or not user_3:
                            user_match = True  # 用户信息缺失，允许关联
                        
                        if user_match and timestamp_3:
                            try:
                                ts3 = parse_datetime(timestamp_3)
                                if ts2 <= ts3:  # 时间顺序正确
                                    time_diff = (ts3 - ts2).total_seconds()
                                    if min_time_diff_3 is None or time_diff < min_time_diff_3:
                                        min_time_diff_3 = time_diff
                                        best_e3 = e3
                            except:
                                pass
            
            if not best_e3:
                continue  # 没有找到匹配的Query3事件
            
            # 检查用户一致性（三个事件的用户应该相同）
            event_1 = best_e1.get('event', {})
            event_3 = best_e3.get('event', {})
            user_1 = event_1.get('user', {}).get('name')
            user_3 = event_3.get('user', {}).get('name')
            
            users_match = True
            if user_1 and user_2 and user_3:
                users_match = (user_1 == user_2 == user_3)
            elif user_1 and user_2:
                users_match = (user_1 == user_2)
            elif user_2 and user_3:
                users_match = (user_2 == user_3)
            
            if users_match:
                # 构建 correlation_id
                corr_key = f"{best_e1.get('id', '')}-{e2.get('id', '')}-{best_e3.get('id', '')}"
                corr_id = f"corr-{hashlib.md5(corr_key.encode()).hexdigest()[:16]}"
                
                # 检查是否已经存在相同的关联（避免重复）
                existing_corr_ids = {c.get('correlation_id') for c in correlations}
                if corr_id in existing_corr_ids:
                    continue  # 已存在，跳过
                
                # 计算综合置信度（基于分级判断）
                level_1 = best_e1.get('privilege_level', 0)
                level_2 = e2.get('privilege_level', 0)
                level_3 = best_e3.get('privilege_level', 0)
                conf_1 = best_e1.get('privilege_confidence', 0.0)
                conf_2 = e2.get('privilege_confidence', 0.0)
                conf_3 = best_e3.get('privilege_confidence', 0.0)
                
                # 三个事件关联，基础分数更高
                base_score = 0.9
                if level_1 > 0 or level_2 > 0 or level_3 > 0:
                    # 提升置信度（基于分级判断）
                    privilege_boost = max(conf_1, conf_2, conf_3) * 0.1  # 最多提升 0.1
                    base_score = min(base_score + privilege_boost, 1.0)
                
                correlations.append({
                    "correlation_id": corr_id,
                    "rule_id": rule.get('name', 'unknown'),
                    "rule_name": rule.get('name', 'unknown'),
                    "timestamp": event_1.get('@timestamp'),
                    "events": [best_e1, e2, best_e3],  # 改为 events
                    "findings": [best_e1, e2, best_e3],  # 保持兼容性，但实际是 events
                    "score": base_score,  # 基于分级判断的分数
                    "privilege_levels": [level_1, level_2, level_3],  # 记录分级信息
                    "privilege_confidences": [conf_1, conf_2, conf_3]
                })
    
    rule_name = rule.get('name', 'unknown')
    print(f"[DEBUG] 应用规则 '{rule_name}' 找到 {len(correlations)} 个关联")
    
    # 统计信息：帮助诊断为什么会有这么多关联
    if len(query_results) >= 3:
        events_1_count = len(query_results[0].get('events', []))
        events_2_count = len(query_results[1].get('events', []))
        events_3_count = len(query_results[2].get('events', []))
        print(f"[DEBUG] 关联统计: Query1={events_1_count}个事件, Query2={events_2_count}个事件, Query3={events_3_count}个事件")
        print(f"[DEBUG] 理论最大关联数（笛卡尔积）: {events_1_count * events_2_count * events_3_count}")
        print(f"[DEBUG] 实际关联数: {len(correlations)}")
        if len(correlations) > 0:
            # 统计唯一的主机组合
            unique_host_combos = set()
            for corr in correlations[:10]:  # 只检查前10个
                events = corr.get('events', [])
                if len(events) >= 3:
                    host_1 = events[0].get('event', {}).get('host', {}).get('name', 'unknown')
                    host_2 = events[1].get('event', {}).get('host', {}).get('name', 'unknown')
                    host_3 = events[2].get('event', {}).get('host', {}).get('name', 'unknown')
                    unique_host_combos.add(f"{host_1}->{host_2}->{host_3}")
            print(f"[DEBUG] 前10个关联的唯一主机组合数: {len(unique_host_combos)}")
            if unique_host_combos:
                print(f"[DEBUG] 示例主机组合: {list(unique_host_combos)[:3]}")
    
    return correlations


def query_correlation_results(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    rule_id: Optional[str] = None,
    limit: int = 100,
    use_opensearch_api: bool = True
) -> List[Dict[str, Any]]:
    """
    查询 Correlation 结果
    
    实现方式（按优先级）：
    1. 优先使用 OpenSearch Security Analytics API：GET /_plugins/_security_analytics/correlations?start_timestamp=...&end_timestamp=...
    2. 如果 API 不支持，回退到手动应用规则
    
    参数：
    - start_time: 开始时间（默认：当前时间往前推时间窗口）
    - end_time: 结束时间（默认：当前时间）
    - rule_id: 规则ID（可选，过滤特定规则）
    - limit: 返回结果数量限制
    - use_opensearch_api: 是否优先使用 OpenSearch API（默认 True）
    
    返回: List[correlation_result]
    """
    client = get_client()
    
    # 确保 HTTP 行长度限制足够大（避免 URL 过长错误）
    _ensure_http_line_length_setting(client)
    
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    if start_time is None:
        start_time = end_time - timedelta(minutes=CORRELATION_TIME_WINDOW_MINUTES)
    
    # 方式1: 使用 OpenSearch Security Analytics API（POST with body to avoid URL length limit）
    if use_opensearch_api:
        try:
            # 转换为毫秒时间戳（epoch milliseconds）
            start_timestamp_ms = int(start_time.timestamp() * 1000)
            end_timestamp_ms = int(end_time.timestamp() * 1000)
            
            # 使用 POST 请求，将参数放在 body 中，避免 URL 过长（超过 4096 字节）
            # 这样可以避免 "too_long_http_line_exception" 错误
            request_body = {
                "start_timestamp": start_timestamp_ms,
                "end_timestamp": end_timestamp_ms
            }
            
            # 如果指定了 rule_id，添加到 body 中
            if rule_id:
                request_body["rule_id"] = rule_id
            
            # 尝试 POST 请求（避免 URL 过长）
            try:
                response = client.transport.perform_request(
                    'POST',
                    CORRELATION_RESULTS_API,
                    body=request_body
                )
            except Exception as post_error:
                # 如果 POST 不支持，回退到 GET（但限制参数长度）
                print(f"[WARNING] POST 请求失败，尝试 GET: {post_error}")
                # 构建 URL（使用 query parameters，但限制长度）
                url = f"{CORRELATION_RESULTS_API}?start_timestamp={start_timestamp_ms}&end_timestamp={end_timestamp_ms}"
                if rule_id and len(url) + len(rule_id) < 3000:  # 确保URL不会太长
                    url += f"&rule_id={rule_id}"
                
                response = client.transport.perform_request(
                    'GET',
                    url
                )
            
            # 调试：打印原始响应结构
            print(f"[DEBUG] OpenSearch API 原始响应类型: {type(response)}")
            if isinstance(response, dict):
                print(f"[DEBUG] 原始响应 keys: {list(response.keys())}")
                print(f"[DEBUG] 原始响应内容（前500字符）: {str(response)[:500]}")
            elif isinstance(response, list):
                print(f"[DEBUG] 原始响应是列表，长度: {len(response)}")
                if response:
                    print(f"[DEBUG] 第一个元素类型: {type(response[0])}")
                    if isinstance(response[0], dict):
                        print(f"[DEBUG] 第一个元素的 keys: {list(response[0].keys())}")
            
            # 解析响应（可能是数组或对象）
            correlations = []
            if isinstance(response, list):
                correlations = response
            elif isinstance(response, dict):
                # 可能是 {"correlations": [...]} 或 {"hits": {"hits": [...]}}
                if "correlations" in response:
                    correlations = response["correlations"]
                elif "hits" in response:
                    hits = response["hits"].get("hits", [])
                    for hit in hits:
                        source = hit.get("_source", {})
                        correlations.append({
                            "correlation_id": hit.get("_id"),
                            "rule_id": source.get("rule_id"),
                            "rule_name": source.get("rule_name"),
                            "timestamp": source.get("@timestamp"),
                            "findings": source.get("findings", []),
                            "score": source.get("score", 0.0)
                        })
                else:
                    # 直接是 correlation 对象
                    correlations = [response] if response else []
            
            if correlations:
                print(f"[INFO] 从 OpenSearch API 获取到 {len(correlations)} 个 correlation 结果")
                # 调试：打印第一个 correlation 的完整结构
                if correlations:
                    first_corr = correlations[0]
                    print(f"[DEBUG] 第一个 correlation 的 keys: {list(first_corr.keys())}")
                    print(f"[DEBUG] 第一个 correlation 的完整内容: {first_corr}")
                    
                    # 检查各种可能的字段
                    for key in ['findings', 'events', 'correlated_findings', 'findings_list', 'related_findings']:
                        if key in first_corr:
                            value = first_corr[key]
                            print(f"[DEBUG] {key}: 类型={type(value)}, 长度={len(value) if isinstance(value, (list, dict)) else 'N/A'}")
                            if isinstance(value, list) and value:
                                print(f"[DEBUG] {key}[0] 的类型: {type(value[0])}")
                                if isinstance(value[0], dict):
                                    print(f"[DEBUG] {key}[0] 的 keys: {list(value[0].keys())[:10]}")
                return correlations[:limit]
            
        except Exception as e:
            print(f"[WARNING] 从 OpenSearch API 查询 Correlation 结果失败: {e}")
            print(f"[INFO] 回退到手动应用规则模式")
            use_opensearch_api = False
    
    # 方式2: 手动应用规则（回退方案）
    if not use_opensearch_api:
        # 获取 correlation rule
        # 注意：OpenSearch API 不支持 GET 方法获取单个规则，需要使用 POST 搜索
        rule = None
        if rule_id:
            try:
                # 使用 POST 搜索端点查询特定规则
                search_response = client.transport.perform_request(
                    'POST',
                    f"{CORRELATION_RULES_API}/_search",
                    body={
                        "query": {
                            "ids": {
                                "values": [rule_id]
                            }
                        },
                        "size": 1
                    }
                )
                # 解析响应
                if isinstance(search_response, dict):
                    hits = search_response.get("hits", {}).get("hits", [])
                    if hits:
                        rule = hits[0].get("_source", {})
                        print(f"[INFO] 通过搜索找到规则 (ID: {rule_id})")
            except Exception as e:
                print(f"[WARNING] 获取规则失败: {e}")
        
        # 如果没有指定 rule_id 或未找到，尝试搜索横向移动规则
        if not rule:
            try:
                # 使用 POST 搜索端点查询规则（GET 方法不支持）
                search_response = client.transport.perform_request(
                    'POST',
                    f"{CORRELATION_RULES_API}/_search",
                    body={
                        "query": {
                            "match": {
                                "name": "Lateral Movement Detection"
                            }
                        },
                        "size": 10
                    }
                )
                # 解析响应
                existing_rules = []
                if isinstance(search_response, dict):
                    hits = search_response.get("hits", {}).get("hits", [])
                    if hits:
                        rule = hits[0].get("_source", {})
                        rule_id = hits[0].get("_id")
                        if rule:
                            print(f"[INFO] 找到横向移动规则 (ID: {rule_id})")
                elif isinstance(search_response, list):
                    existing_rules = search_response
                elif isinstance(search_response, dict):
                    if "rules" in search_response:
                        existing_rules = search_response["rules"]
                    elif "hits" in search_response:
                        existing_rules = [hit.get("_source", {}) for hit in search_response["hits"].get("hits", [])]
                
                # 查找横向移动规则
                for r in existing_rules:
                    if isinstance(r, dict) and r.get("name") == "Lateral Movement Detection":
                        rule = r
                        break
            except Exception as e:
                print(f"[WARNING] 查询规则失败: {e}")
        
        # 如果找到了规则，手动应用（在 events 索引中）
        if rule:
            return apply_correlation_rule_manually(
                rule=rule,
                start_time=start_time,
                end_time=end_time,
                events_index_pattern=f"{INDEX_PATTERNS['ECS_EVENTS']}-*"  # 明确指定 events 索引
            )
        else:
            print(f"[WARNING] 未找到 Correlation Rule，无法应用")
            return []
    
    return []


# ========== 关联链聚合 ==========

def aggregate_correlation_chains(
    correlations: List[Dict[str, Any]],
    events_index_pattern: str = None
) -> List[Dict[str, Any]]:
    """
    聚合关联边，生成攻击链
    
    参数：
    - correlations: Correlation 结果列表（包含关联的 events）
    - events_index_pattern: Events 索引模式（用于查询详细 event 信息，可选）
    
    返回: List[chain] 每个 chain 包含：
    {
        "chain_id": str,
        "events": List[dict],    # 关联的 events（原始事件）
        "hosts": List[str],      # 涉及的主机
        "src_ip": str,           # 源IP
        "dst_ip": str,           # 目标IP
        "user": str,             # 用户（如果可关联）
        "timeline": List[dict],  # 时间线
        "confidence": float      # 置信度
    }
    """
    chains = []
    
    for correlation in correlations:
        # 调试：打印 correlation 结构
        print(f"[DEBUG] 处理 correlation: {correlation.get('correlation_id', 'unknown')}")
        print(f"[DEBUG] Correlation keys: {list(correlation.keys())}")
        
        # correlation 结果中已经包含了 events（或 findings，但实际是 events）
        # OpenSearch API 返回的格式可能是：
        # - {"findings": [...]} 或 {"events": [...]} 或 {"correlated_findings": [...]}
        events_refs = (
            correlation.get('events', []) or 
            correlation.get('findings', []) or 
            correlation.get('correlated_findings', []) or
            correlation.get('findings_list', [])
        )
        
        print(f"[DEBUG] 找到 {len(events_refs)} 个 events/findings")
        if events_refs:
            print(f"[DEBUG] 第一个 event/finding 的 keys: {list(events_refs[0].keys()) if isinstance(events_refs[0], dict) else 'not a dict'}")
        
        if len(events_refs) < 2:  # 至少需要2个 events 才能形成链
            print(f"[DEBUG] 跳过：events 数量不足 ({len(events_refs)} < 2)")
            continue
        
        # 直接使用 correlation 结果中的 events（不需要重新查询）
        events_data = []
        hosts = set()
        src_ips = set()
        dst_ips = set()
        users = set()
        timeline = []
        
        for event_ref in events_refs:
            # event_ref 可能是 {"id": "...", "event": {...}} 或直接是 event dict
            if isinstance(event_ref, dict):
                event = event_ref.get('event', event_ref)  # 兼容两种格式
                event_id = event_ref.get('id') or event_ref.get('_id')
            else:
                continue
            
            # 提取主机信息
            host_id = event.get('host', {}).get('id') or event.get('host.id')
            if host_id:
                hosts.add(host_id)
            
            # 提取IP信息
            src_ip = event.get('source', {}).get('ip') or event.get('source.ip')
            dst_ip = event.get('destination', {}).get('ip') or event.get('destination.ip')
            if src_ip:
                src_ips.add(src_ip)
            if dst_ip:
                dst_ips.add(dst_ip)
            
            # 提取用户信息
            user = event.get('user', {}).get('name') or event.get('user.name')
            if user:
                users.add(user)
            
            # 提取时间戳
            timestamp = event.get('@timestamp') or event.get('event', {}).get('created')
            
            # 提取事件类型信息
            event_category = event.get('event', {}).get('category', [])
            event_type = event.get('event', {}).get('type', [])
            event_action = event.get('event', {}).get('action', '')
            
            events_data.append({
                "event_id": event_id,
                "event": event
            })
            
            timeline.append({
                "timestamp": timestamp,
                "event_id": event_id,
                "host": host_id,
                "category": event_category,
                "type": event_type,
                "action": event_action,
                "summary": event.get('message', '')[:100] if event.get('message') else f"{event_category} - {event_action}"
            })
        
        # 按时间排序 timeline
        timeline.sort(key=lambda x: x.get('timestamp', ''))
        
        # 判断是否满足横向移动条件
        # 条件1: 至少涉及2个不同主机
        # 条件2: 有源IP和目标IP（跨主机连接）
        # 条件3: 时间顺序合理
        
        if len(hosts) >= 2 and (len(src_ips) > 0 or len(dst_ips) > 0):
            # 计算置信度（基于分级判断）
            base_confidence = min(0.5 + (len(events_data) * 0.1), 1.0)
            
            # 从 correlation 结果中提取分级信息
            privilege_levels = correlation.get('privilege_levels', [])
            privilege_confidences = correlation.get('privilege_confidences', [])
            
            # 如果有分级信息，提升置信度
            if privilege_levels:
                max_level = max(privilege_levels)
                max_conf = max(privilege_confidences) if privilege_confidences else 0.0
                
                # Level 2 或更高，提升置信度
                if max_level >= 2:
                    base_confidence = min(base_confidence + 0.1, 1.0)
                # Level 1，小幅提升
                elif max_level >= 1:
                    base_confidence = min(base_confidence + max_conf * 0.1, 1.0)
            
            chain = {
                "chain_id": f"chain-{hashlib.md5(str(correlation.get('correlation_id', '')).encode()).hexdigest()[:16]}",
                "events": events_data,  # 改为 events
                "findings": events_data,  # 保持兼容性
                "hosts": sorted(list(hosts)),
                "src_ip": list(src_ips)[0] if src_ips else None,
                "dst_ip": list(dst_ips)[0] if dst_ips else None,
                "user": list(users)[0] if users else None,
                "timeline": timeline,
                "confidence": base_confidence,  # 基于分级判断的置信度
                "correlation_id": correlation.get('correlation_id'),
                "privilege_levels": privilege_levels,  # 记录分级信息
                "privilege_confidences": privilege_confidences
            }
            
            chains.append(chain)
    
    return chains


# ========== 生成高层事件 ==========

def generate_lateral_movement_finding(
    chain: Dict[str, Any],
    timestamp: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    生成横向移动高层事件（Finding）
    
    参数：
    - chain: 攻击链数据（来自 aggregate_correlation_chains）
    - timestamp: 事件时间戳（默认：当前时间）
    
    返回: ECS 格式的 Finding
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    
    timestamp_str = to_rfc3339(timestamp)
    
    # 提取相关 findings 的 event_ids
    related_event_ids = []
    related_finding_ids = []
    
    # 从 chain 中提取 events（chain 现在包含的是 events，不是 findings）
    for event_data in chain.get('events', chain.get('findings', [])):
        event = event_data.get('event', event_data)
        event_id = event_data.get('event_id') or event_data.get('finding_id')
        
        if event_id:
            related_finding_ids.append(event_id)  # 保持字段名兼容
        
        # 提取 event.id（ECS 格式）
        ecs_event_id = event.get('event', {}).get('id')
        if ecs_event_id:
            related_event_ids.append(ecs_event_id)
    
    # 生成 finding ID
    chain_id = chain.get('chain_id', 'unknown')
    finding_id = f"lateral-movement-{hashlib.md5(chain_id.encode()).hexdigest()[:16]}"
    
    # 构建时间线摘要
    timeline_summary = []
    for item in chain.get('timeline', []):
        timeline_summary.append({
            "ts": item.get('timestamp'),
            "type": item.get('technique_id', 'unknown'),
            "finding_id": item.get('finding_id'),
            "host": item.get('host'),
            "summary": item.get('summary', '')
        })
    
    # 根据分级判断结果调整置信度和严重性
    privilege_levels = chain.get('privilege_levels', [])
    privilege_confidences = chain.get('privilege_confidences', [])
    
    # 计算平均级别和置信度
    avg_level = sum(privilege_levels) / len(privilege_levels) if privilege_levels else 0
    avg_confidence = sum(privilege_confidences) / len(privilege_confidences) if privilege_confidences else chain.get('confidence', 0.7)
    
    # 根据级别调整严重性
    # Level 1: 60, Level 2: 70, Level 3: 80
    if avg_level >= 3:
        severity = 80
    elif avg_level >= 2:
        severity = 70
    elif avg_level >= 1:
        severity = 60
    else:
        severity = 50
    
    # 构建 ECS Finding
    ecs_finding = {
        "@timestamp": timestamp_str,
        "ecs": {"version": "9.2.0"},
        "event": {
            "id": finding_id,
            "kind": "alert",
            "created": timestamp_str,
            "ingested": timestamp_str,
            "category": ["intrusion_detection"],
            "type": ["alert"],
            "action": "lateral_movement_detection",
            "dataset": "finding.correlated.lateral_movement",
            "severity": severity,  # 基于分级判断的严重性
        },
        "rule": {
            "id": "correlation-rule-lateral-movement",
            "name": "Lateral Movement Detection",
            "version": "1.0",
        },
        "threat": {
            "tactic": {
                "id": LATERAL_MOVEMENT_TACTIC_ID,
                "name": LATERAL_MOVEMENT_TACTIC_NAME
            },
            "technique": {
                "id": LATERAL_MOVEMENT_TECHNIQUE_ID,
                "name": "Remote Services"
            }
        },
        "custom": {
            "finding": {
                "stage": "correlated",
                "providers": ["correlation_rules"],
                "fingerprint": fingerprint_id_from_key(
                    f"{LATERAL_MOVEMENT_TECHNIQUE_ID}|{chain.get('src_ip', 'unknown')}|{chain.get('dst_ip', 'unknown')}|{chain.get('user', 'unknown')}|{int(timestamp.timestamp() // (CORRELATION_TIME_WINDOW_MINUTES * 60))}"
                )
            },
            "confidence": avg_confidence,  # 使用基于分级判断的置信度
            "privilege_escalation": {
                "levels": privilege_levels,  # 记录分级信息
                "confidences": privilege_confidences,
                "average_level": avg_level,
                "has_followup_operations": chain.get('has_followup_privilege_operations', False)
            },
            "evidence": {
                "event_ids": list(set(related_event_ids)),  # 去重
                "finding_ids": related_finding_ids,
                "chain_id": chain_id
            },
            "lateral_movement": {
                "hosts": chain.get('hosts', []),
                "src_ip": chain.get('src_ip'),
                "dst_ip": chain.get('dst_ip'),
                "user": chain.get('user'),
                "timeline": timeline_summary,
                "findings_count": len(chain.get('findings', []))
            }
        },
        "message": f"检测到横向移动攻击：从 {chain.get('src_ip', 'unknown')} 到 {chain.get('dst_ip', 'unknown')}，涉及 {len(chain.get('hosts', []))} 个主机"
    }
    
    # 添加主机信息（如果有）
    if chain.get('hosts'):
        ecs_finding["host"] = {
            "id": chain.get('hosts')[0],  # 主主机
            "name": chain.get('hosts')[0]
        }
    
    # 添加网络信息（如果有）
    if chain.get('src_ip') or chain.get('dst_ip'):
        if "source" not in ecs_finding:
            ecs_finding["source"] = {}
        if "destination" not in ecs_finding:
            ecs_finding["destination"] = {}
        
        if chain.get('src_ip'):
            ecs_finding["source"]["ip"] = chain.get('src_ip')
        if chain.get('dst_ip'):
            ecs_finding["destination"]["ip"] = chain.get('dst_ip')
    
    return ecs_finding


# ========== 主分析函数 ==========

def run_correlation_analysis(
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES,
    create_rules_if_not_exists: bool = True,
    create_all_rules: bool = True,
    rule_name: str = None
) -> dict[str, Any]:
    """
    运行 Correlation 分析
    
    功能：
    1. 检查并设置预定义规则和detector（Security Analytics）
    2. 运行 Security Analytics 检测（扫描并获取findings）
    3. 确保 Correlation Rules 存在（如果不存在则创建）
    4. 查询最近的 Correlation 结果
    5. 聚合关联链
    6. 生成高层事件
    7. 写入 Raw Findings 索引
    
    参数：
    - time_window_minutes: 查询时间窗口（分钟）
    - create_rules_if_not_exists: 如果规则不存在是否创建
    - create_all_rules: 是否创建所有预定义规则（True）或仅创建指定规则（False）
    - rule_name: 如果 create_all_rules=False，指定要创建的单个规则名称
    
    返回: {
        "correlations_found": int,
        "chains_aggregated": int,
        "findings_generated": int,
        "errors": int,
        "rules_created": dict  # 规则创建结果
    }
    """
    client = get_client()
    today = datetime.now(timezone.utc)
    raw_index_name = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
    
    try:
        # Step 1: 检查并设置预定义规则和detector（在correlation之前）
        print("[INFO] 检查预定义规则和detector...")
        rules_detectors_ready = _check_and_setup_rules_detectors()
        if not rules_detectors_ready:
            print("[WARNING] 规则或detector未就绪，但继续执行correlation分析")
        
        # Step 2: 运行 Security Analytics 检测（扫描并获取findings）
        print("[INFO] 运行 Security Analytics 检测...")
        sa_result = run_security_analytics(trigger_scan=True, force_scan=False)
        if sa_result.get("success"):
            print(f"[INFO] Security Analytics 检测完成: {sa_result.get('stored', 0)} 条findings已存储")
        else:
            print(f"[WARNING] Security Analytics 检测失败或跳过: {sa_result.get('message', '')}")
        
        # Step 3: 确保索引存在
        if not index_exists(raw_index_name):
            print(f"[INFO] Raw Findings 索引不存在: {raw_index_name}，跳过分析")
            return {
                "correlations_found": 0,
                "chains_aggregated": 0,
                "findings_generated": 0,
                "errors": 0,
                "rules_created": {}
            }
        
        # Step 4: 确保 Correlation Rules 存在
        rules_created_result = {}
        if create_rules_if_not_exists:
            if create_all_rules:
                print("[INFO] 创建所有预定义 Correlation Rules...")
                rules_created_result = create_all_correlation_rules(
                    time_window_minutes=time_window_minutes
                )
                print(f"[INFO] Correlation Rules 创建完成: {rules_created_result.get('successful', 0)}/{rules_created_result.get('total', 0)} 成功")
            elif rule_name:
                # 创建单个指定规则（只保留最重要的规则）
                rule_func_map = {
                    "Lateral Movement Detection": create_lateral_movement_correlation_rule,  # 必须保留
                    "Privilege Escalation Detection": create_privilege_escalation_correlation_rule,  # 重要
                    "Data Exfiltration Detection": create_data_exfiltration_correlation_rule,  # 重要
                }
                
                if rule_name in rule_func_map:
                    rule_result = rule_func_map[rule_name](
                        rule_name=rule_name,
                        time_window_minutes=time_window_minutes
                    )
                    rules_created_result = {
                        "success": rule_result.get("success"),
                        "rules_created": [{
                            "name": rule_name,
                            "success": rule_result.get("success"),
                            "rule_id": rule_result.get("rule_id"),
                            "message": rule_result.get("message")
                        }],
                        "total": 1,
                        "successful": 1 if rule_result.get("success") else 0,
                        "failed": 0 if rule_result.get("success") else 1
                    }
                else:
                    print(f"[WARNING] 未知的规则名称: {rule_name}")
                    rules_created_result = {"success": False, "rules_created": [], "total": 0, "successful": 0, "failed": 0}
        
        # Step 5: 查询 Correlation 结果
        # 优先使用 OpenSearch Security Analytics API，如果不支持则回退到手动应用
        end_time = datetime.now(timezone.utc)
        # 增加时间窗口，确保能匹配到最近生成的events（默认30分钟可能不够）
        # 如果events是最近1小时内生成的，使用60分钟窗口
        effective_time_window = max(time_window_minutes, 60)  # 至少60分钟
        start_time = end_time - timedelta(minutes=effective_time_window)
        
        # 收集所有成功创建的规则ID
        rule_ids_to_query = []
        if rules_created_result.get("rules_created"):
            for rule_result in rules_created_result["rules_created"]:
                if rule_result.get("success") and rule_result.get("rule_id"):
                    rule_ids_to_query.append(rule_result.get("rule_id"))
        
        # 如果没有规则ID，尝试查询横向移动规则（向后兼容）
        if not rule_ids_to_query and not create_all_rules and rule_name == "Lateral Movement Detection":
            lateral_result = create_lateral_movement_correlation_rule(
                rule_name="Lateral Movement Detection",
                time_window_minutes=time_window_minutes
            )
            if lateral_result.get("success") and lateral_result.get("rule_id"):
                rule_ids_to_query.append(lateral_result.get("rule_id"))
        
        # 查询所有规则的结果
        all_correlations = []
        for rule_id in rule_ids_to_query:
            try:
                correlations = query_correlation_results(
                    start_time=start_time,
                    end_time=end_time,
                    rule_id=rule_id,
                    limit=100,
                    use_opensearch_api=False  # 强制使用手动应用规则模式（在 events 索引中查询）
                )
                all_correlations.extend(correlations)
                print(f"[INFO] 规则 {rule_id} 找到 {len(correlations)} 个 Correlation 结果")
            except Exception as e:
                print(f"[WARNING] 查询规则 {rule_id} 的 Correlation 结果失败: {e}")
                continue
        
        correlations = all_correlations
        print(f"[INFO] 总共找到 {len(correlations)} 个 Correlation 结果")
        
        if len(correlations) == 0:
            return {
                "correlations_found": 0,
                "chains_aggregated": 0,
                "findings_generated": 0,
                "errors": 0,
                "rules_created": rules_created_result
            }
        
        # Step 6: 聚合关联链（基于 events）
        chains = aggregate_correlation_chains(correlations)
        print(f"[INFO] 聚合了 {len(chains)} 个攻击链（基于 events）")
        
        if len(chains) == 0:
            return {
                "correlations_found": len(correlations),
                "chains_aggregated": 0,
                "findings_generated": 0,
                "errors": 0,
                "rules_created": rules_created_result
            }
        
        # Step 7: 生成高层事件并写入
        findings_to_index = []
        errors = 0
        
        for chain in chains:
            try:
                # 根据chain类型生成不同类型的finding（目前主要支持横向移动）
                finding = generate_lateral_movement_finding(chain)
                findings_to_index.append({
                    "id": finding.get("event", {}).get("id"),
                    "document": finding
                })
            except Exception as e:
                print(f"[ERROR] 生成 Finding 失败: {e}")
                errors += 1
                continue
        
        # Step 8: 批量写入 Raw Findings
        if len(findings_to_index) > 0:
            result = bulk_index(raw_index_name, findings_to_index)
            if result.get("success", 0) > 0:
                refresh_index(raw_index_name)
                print(f"[INFO] 成功写入 {result.get('success', 0)} 个 Correlation Finding")
            
            return {
                "correlations_found": len(correlations),
                "chains_aggregated": len(chains),
                "findings_generated": result.get("success", 0),
                "errors": errors + result.get("failed", 0),
                "rules_created": rules_created_result
            }
        
        return {
            "correlations_found": len(correlations),
            "chains_aggregated": len(chains),
            "findings_generated": 0,
            "errors": errors,
            "rules_created": rules_created_result
        }
        
    except Exception as e:
        print(f"[ERROR] Correlation 分析失败: {e}")
        import traceback
        traceback.print_exc()
        return {
            "correlations_found": 0,
            "chains_aggregated": 0,
            "findings_generated": 0,
            "errors": 1,
            "rules_created": rules_created_result if 'rules_created_result' in locals() else {}
        }


# ========== 告警融合去重（保留）==========

def select_most_credible_finding(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    从多个 findings 中选择最可信的一个
    
    可信度评分规则（优先级从高到低）：
    1. confidence 值（custom.confidence）
    2. severity 值（event.severity）
    3. 时间戳（越新越好）
    
    参数：
    - findings: Finding 列表
    
    返回: 最可信的 finding
    """
    if len(findings) == 0:
        raise ValueError("无法从空列表中选择 finding")
    if len(findings) == 1:
        return findings[0]
    
    def get_credibility_score(finding: dict[str, Any]) -> tuple[float, int, str]:
        """计算可信度分数，返回 (confidence, severity, timestamp) 用于排序"""
        # confidence (0.0-1.0)，越高越好
        confidence = finding.get("custom", {}).get("confidence", 0.0)
        if not isinstance(confidence, (int, float)):
            confidence = 0.0
        
        # severity (0-100)，越高越好
        severity = finding.get("event", {}).get("severity", 0)
        if not isinstance(severity, (int, float)):
            severity = 0
        
        # timestamp，越新越好（用于排序）
        timestamp = finding.get("@timestamp") or finding.get("event", {}).get("created", "")
        
        return (confidence, severity, timestamp)
    
    # 按可信度排序：confidence 降序，severity 降序，timestamp 降序
    sorted_findings = sorted(
        findings,
        key=get_credibility_score,
        reverse=True
    )
    
    return sorted_findings[0]


def deduplicate_findings() -> dict[str, Any]:
    """
    告警融合去重（Raw Findings → Canonical Findings）
    根据文档：在时间窗 Δt 内，将满足相同指纹的 Raw Finding 合并为一条 Canonical Finding
    
    融合策略：多个 finding 融合时，选择最可信的 finding，直接使用其 source 数据作为新 finding 的 source
    """
    client = get_client()
    today = datetime.now(timezone.utc)
    raw_index_name = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
    canonical_index_name = get_index_name(INDEX_PATTERNS["CANONICAL_FINDINGS"], today)

    try:
        # 检查 raw-findings 索引是否存在
        if not index_exists(raw_index_name):
            print(f"[INFO] Raw Findings索引不存在: {raw_index_name}，跳过去重")
            return {"total": 0, "merged": 0, "canonical": 0, "errors": 0}
        
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
                # 多个 findings 需要融合：选择最可信的 finding
                most_credible = select_most_credible_finding(findings)
                import copy
                canonical = copy.deepcopy(most_credible)
                
                # 收集所有 findings 的 providers 和 event_ids
                providers = set()
                event_ids = set()
                
                for f in findings:
                    # 收集 providers
                    f_custom = f.get("custom", {})
                    f_finding = f_custom.get("finding", {})
                    f_providers = f_finding.get("providers", [])
                    if isinstance(f_providers, list):
                        providers.update(f_providers)
                    provider = extract_provider(f)
                    if provider != "unknown":
                        providers.add(provider)
                    
                    # 收集 event_ids
                    f_evidence = f_custom.get("evidence", {})
                    f_event_ids = f_evidence.get("event_ids", [])
                    if isinstance(f_event_ids, list):
                        event_ids.update(f_event_ids)
                
                # 更新 canonical finding 的字段
                if "custom" not in canonical:
                    canonical["custom"] = {}
                if "finding" not in canonical["custom"]:
                    canonical["custom"]["finding"] = {}
                
                canonical["custom"]["finding"]["stage"] = "canonical"
                canonical["custom"]["finding"]["providers"] = sorted(p for p in providers if isinstance(p, str) and p)
                canonical["custom"]["finding"]["fingerprint"] = fingerprint_id_from_key(fingerprint)
                
                # 更新 evidence.event_ids（合并所有 findings 的 event_ids）
                if "evidence" not in canonical["custom"]:
                    canonical["custom"]["evidence"] = {}
                canonical["custom"]["evidence"]["event_ids"] = sorted(e for e in event_ids if isinstance(e, str) and e)
                
                # 更新 severity（取最大值）
                max_severity = canonical.get("event", {}).get("severity", 0) or 0
                for f in findings:
                    severity = f.get("event", {}).get("severity", 0) or 0
                    if severity > max_severity:
                        max_severity = severity
                
                if "event" in canonical:
                    canonical["event"]["severity"] = max_severity
                else:
                    canonical["event.severity"] = max_severity
                
                # 更新 dataset 和 kind
                if "event" in canonical:
                    canonical["event"]["dataset"] = "finding.canonical"
                    canonical["event"]["kind"] = "alert"
                else:
                    canonical["event.dataset"] = "finding.canonical"
                    canonical["event.kind"] = "alert"
                
                # 更新 confidence（根据来源数量调整）
                base_confidence = canonical.get("custom", {}).get("confidence", 0.5)
                confidence = min(base_confidence + (len(providers) * 0.1), 1.0)
                canonical["custom"]["confidence"] = confidence
                
                canonical_findings.append(canonical)
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

        # Canonical Finding 是中心侧生成的"新文档"，入库时间应为生成时刻。
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
            if result.get("success", 0) > 0:
                refresh_index(canonical_index_name)
                print(f"[INFO] 成功写入 {result.get('success', 0)} 个 Canonical Findings 到 {canonical_index_name}")

            return {
                "total": len(raw_findings),
                "merged": merged_count,
                "canonical": len(normalized_canonicals),
                "errors": result.get("failed", 0),
            }

        return {"total": len(raw_findings), "merged": merged_count, "canonical": 0, "errors": 0}
    except Exception as error:
        error_str = str(error)
        if 'index_not_found' in error_str.lower() or '404' in error_str:
            print(f"[INFO] Raw Findings索引不存在，跳过去重: {raw_index_name}")
            return {"total": 0, "merged": 0, "canonical": 0, "errors": 0}
        print(f"告警融合去重失败: {error}")
        raise


def merge_findings_only() -> dict[str, Any]:
    """
    仅执行融合去重，不做其他分析
    """
    return deduplicate_findings()


# ========== 主入口函数（兼容旧接口）==========

def run_data_analysis(
    trigger_correlation: bool = True,
    time_window_minutes: int = CORRELATION_TIME_WINDOW_MINUTES
) -> dict[str, Any]:
    """
    数据分析主函数（新版本：基于 Correlation Rules）
    
    功能：
    1. 运行 Correlation 分析（按需触发）
    2. 告警融合去重（Raw → Canonical）
    
    参数：
    - trigger_correlation: 是否触发 Correlation 分析（默认 True）
    - time_window_minutes: Correlation 时间窗口（分钟）
    
    返回: {
        "correlation": dict,      # Correlation 分析结果
        "deduplication": dict     # 去重结果
    }
    """
    correlation_result = {}
    
    if trigger_correlation:
        correlation_result = run_correlation_analysis(
            time_window_minutes=time_window_minutes,
            create_rules_if_not_exists=True,
            create_all_rules=True  # 创建所有预定义的correlation rules
        )
    
    # 告警融合去重
    print(f"\n[INFO] 开始告警融合去重（Raw Findings → Canonical Findings）...")
    deduplication_result = deduplicate_findings()
    
    if deduplication_result:
        print(f"[INFO] 去重融合完成:")
        print(f"    - 原始 Findings: {deduplication_result.get('total', 0)} 个")
        print(f"    - 融合的 Findings: {deduplication_result.get('merged', 0)} 个")
        print(f"    - 生成的 Canonical Findings: {deduplication_result.get('canonical', 0)} 个")
        if deduplication_result.get('errors', 0) > 0:
            print(f"    - 错误: {deduplication_result.get('errors', 0)} 个")

    return {
        "correlation": correlation_result,
        "deduplication": deduplication_result,
    }
