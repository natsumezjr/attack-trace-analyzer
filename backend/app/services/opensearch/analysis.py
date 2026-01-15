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

# ========== 辅助函数 ==========

def fingerprint_id_from_key(fingerprint_key: str) -> str:
    """
    将用于分组/融合的"原始指纹 key"转换为 docs 约定的 custom.finding.fingerprint。
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
    suspicious_parents = ['chrome.exe', 'firefox.exe', 'outlook.exe', 'thunderbird.exe', 'iexplore.exe', 'edge.exe']
    if parent_name:
        parent_lower = parent_name.lower()
        if any(sp in parent_lower for sp in suspicious_parents):
            level = 2
            confidence = 0.6  # 父进程异常，提高置信度
    
    # Level 3: 提权成功（需要后续事件，单条 event 无法判断）
    # 这个级别需要在 correlation 后处理阶段判断
    # 如果后续有服务创建、计划任务创建等事件，可以提升到 Level 3
    
    return (level, confidence)


# ========== Correlation Rules 管理 ==========

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
    
    # 可疑父进程列表（浏览器、邮件客户端）
    suspicious_parent_processes = [
        "chrome.exe",
        "firefox.exe",
        "edge.exe",
        "iexplore.exe",
        "outlook.exe",
        "thunderbird.exe"
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
        "_exists_:host.id"
    )
    
    # Query2: 从A到B的远程连接事件（Remote Connect）
    query2 = (
        "event.category:network AND "
        "_exists_:source.ip AND "
        "_exists_:destination.ip AND "
        "network.direction:outbound"
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
        "_exists_:host.id"
    )
    
    # ========== 构建 Correlation Rule ==========
    correlation_rule = {
        "name": rule_name,
        "description": "检测横向移动攻击链：A主机提权尝试事件 -> A到B远程连接事件 -> B主机提权尝试/远程执行事件",
        "tags": ["attack.lateral_movement", "attack.t1021"],
        "correlate": [
            {
                "index": events_index_pattern,
                "category": "windows",
                "query": query1
            },
            {
                "index": events_index_pattern,
                "category": "network",
                "query": query2
            },
            {
                "index": events_index_pattern,
                "category": "windows",
                "query": query3
            }
        ]
    }
    
    try:
        # 策略：先检查是否存在同名规则，如果存在则更新，不存在则创建（去重）
        # 注意：OpenSearch Security Analytics API 不支持 GET 方法查询 correlation rules
        # 因此使用 POST 搜索端点查询现有规则
        
        # Step 1: 先查询是否存在同名规则（去重检查）
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
            
            # 解析搜索结果
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
            # 更新现有规则（PUT）
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
                rule_id = None  # 重置，尝试创建
        
        # Step 3: 创建新规则（POST）
        if not rule_id:
            try:
                create_response = client.transport.perform_request(
                    'POST',
                    CORRELATION_RULES_API,
                    body=correlation_rule
                )
                
                # 解析响应获取 rule_id
                rule_id = None
                if isinstance(create_response, dict):
                    rule_id = create_response.get('_id') or create_response.get('id') or create_response.get('rule_id')
                elif isinstance(create_response, str):
                    # 某些版本可能直接返回 rule_id
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
        
        # 将 query string 转换为 DSL query（添加时间范围）
        # query string 格式：如 "event.category:process AND _exists_:host.id"
        # 需要转换为 DSL 并添加时间范围
        dsl_query = {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": query_string
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
            
            hits = response.get('hits', {}).get('hits', [])
            events = []
            for hit in hits:
                event_source = hit.get('_source', {})
                
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
            
            print(f"[DEBUG] Query {i+1} 在 events 索引中找到 {len(events)} 个事件")
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
    # - 有可关联的字段（host.id, source.ip, destination.ip, user.name）
    
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
        # 简化实现：先关联前两个，再关联第三个
        events_1 = query_results[0].get('events', [])
        events_2 = query_results[1].get('events', [])
        events_3 = query_results[2].get('events', [])
        
        # 先找前两个的关联
        # Query1: 主机A上的提权事件（没有网络IP）
        # Query2: 从A到B的网络连接事件（有source.ip和destination.ip）
        # Query3: 主机B上的提权事件（没有网络IP）
        # 
        # 关联逻辑：
        # 1. e1 和 e2：e1在主机A上，e2的source.ip对应主机A，且用户相同
        # 2. e2 和 e3：e2的destination.ip对应主机B，e3在主机B上，且用户相同
        
        for e1 in events_1:
            event_1 = e1.get('event', {})
            host_1 = event_1.get('host', {}).get('id')
            user_1 = event_1.get('user', {}).get('name')
            
            for e2 in events_2:
                event_2 = e2.get('event', {})
                host_2 = event_2.get('host', {}).get('id')
                src_ip_2 = event_2.get('source', {}).get('ip')
                dst_ip_2 = event_2.get('destination', {}).get('ip')
                user_2 = event_2.get('user', {}).get('name')
                
                # 检查 e1 和 e2 是否关联：
                # - e1 在主机A上，e2 的源主机也是主机A（host_1 == host_2）
                # - 用户相同（可选，但增强关联性）
                e1_e2_correlated = False
                if host_1 and host_2 and host_1 == host_2:
                    # 同一主机上的事件，用户相同则关联
                    if user_1 and user_2 and user_1 == user_2:
                        e1_e2_correlated = True
                    elif not user_1 or not user_2:
                        # 如果用户信息缺失，也允许关联（基于主机）
                        e1_e2_correlated = True
                
                if e1_e2_correlated:
                    # 再找第三个
                    for e3 in events_3:
                        event_3 = e3.get('event', {})
                        host_3 = event_3.get('host', {}).get('id')
                        user_3 = event_3.get('user', {}).get('name')
                        
                        # 检查 e2 和 e3 是否关联：
                        # - e2 的 destination.ip 对应主机B（需要通过IP映射或直接检查host_3）
                        # - e3 在主机B上（host_3）
                        # - 用户相同（可选）
                        # 
                        # 注意：由于 e3 没有 source.ip，我们需要通过其他方式关联
                        # 简化：如果 e2 的 destination.ip 存在，且 e3 在不同于 e2 源主机的另一台主机上
                        e2_e3_correlated = False
                        if host_3 and host_2 and host_3 != host_2:
                            # e3 在不同于 e2 源主机的另一台主机上
                            # 如果 e2 有 destination.ip，说明是跨主机连接
                            if dst_ip_2:
                                # 用户相同则关联
                                if user_2 and user_3 and user_2 == user_3:
                                    e2_e3_correlated = True
                                elif not user_2 or not user_3:
                                    # 如果用户信息缺失，也允许关联（基于主机和IP）
                                    e2_e3_correlated = True
                        
                        if e2_e3_correlated:
                            # 检查用户一致性（三个事件的用户应该相同）
                            users_match = True
                            if user_1 and user_2 and user_3:
                                users_match = (user_1 == user_2 == user_3)
                            elif user_1 and user_2:
                                users_match = (user_1 == user_2)
                            elif user_2 and user_3:
                                users_match = (user_2 == user_3)
                            
                            if users_match:
                                # 构建 correlation_id（避免嵌套 f-string）
                                corr_key = f"{e1.get('id', '')}-{e2.get('id', '')}-{e3.get('id', '')}"
                                corr_id = f"corr-{hashlib.md5(corr_key.encode()).hexdigest()[:16]}"
                                
                                # 计算综合置信度（基于分级判断）
                                level_1 = e1.get('privilege_level', 0)
                                level_2 = e2.get('privilege_level', 0)
                                level_3 = e3.get('privilege_level', 0)
                                conf_1 = e1.get('privilege_confidence', 0.0)
                                conf_2 = e2.get('privilege_confidence', 0.0)
                                conf_3 = e3.get('privilege_confidence', 0.0)
                                
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
                                    "events": [e1, e2, e3],  # 改为 events
                                    "findings": [e1, e2, e3],  # 保持兼容性，但实际是 events
                                    "score": base_score,  # 基于分级判断的分数
                                    "privilege_levels": [level_1, level_2, level_3],  # 记录分级信息
                                    "privilege_confidences": [conf_1, conf_2, conf_3]
                                })
    
    rule_name = rule.get('name', 'unknown')
    print(f"[DEBUG] 应用规则 '{rule_name}' 找到 {len(correlations)} 个关联")
    
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
    
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    if start_time is None:
        start_time = end_time - timedelta(minutes=CORRELATION_TIME_WINDOW_MINUTES)
    
    # 方式1: 使用 OpenSearch Security Analytics API（GET with query parameters）
    if use_opensearch_api:
        try:
            # 转换为毫秒时间戳（epoch milliseconds）
            start_timestamp_ms = int(start_time.timestamp() * 1000)
            end_timestamp_ms = int(end_time.timestamp() * 1000)
            
            # 构建 URL（使用 query parameters）
            # 注意：OpenSearch API 不支持 rule_id 参数，只支持时间范围
            url = f"{CORRELATION_RESULTS_API}?start_timestamp={start_timestamp_ms}&end_timestamp={end_timestamp_ms}"
            
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
    create_rule_if_not_exists: bool = True,
    rule_name: str = "Lateral Movement Detection"
) -> dict[str, Any]:
    """
    运行 Correlation 分析
    
    功能：
    1. 确保 Correlation Rule 存在（如果不存在则创建）
    2. 查询最近的 Correlation 结果
    3. 聚合关联链
    4. 生成横向移动高层事件
    5. 写入 Raw Findings 索引
    
    参数：
    - time_window_minutes: 查询时间窗口（分钟）
    - create_rule_if_not_exists: 如果规则不存在是否创建
    - rule_name: Correlation Rule 名称
    
    返回: {
        "correlations_found": int,
        "chains_aggregated": int,
        "findings_generated": int,
        "errors": int
    }
    """
    client = get_client()
    today = datetime.now(timezone.utc)
    raw_index_name = get_index_name(INDEX_PATTERNS["RAW_FINDINGS"], today)
    
    try:
        # Step 1: 确保索引存在
        if not index_exists(raw_index_name):
            print(f"[INFO] Raw Findings 索引不存在: {raw_index_name}，跳过分析")
            return {
                "correlations_found": 0,
                "chains_aggregated": 0,
                "findings_generated": 0,
                "errors": 0
            }
        
        # Step 2: 确保 Correlation Rule 存在
        rule_id = None
        if create_rule_if_not_exists:
            rule_result = create_lateral_movement_correlation_rule(
                rule_name=rule_name,
                time_window_minutes=time_window_minutes
            )
            if rule_result.get("success"):
                rule_id = rule_result.get("rule_id")
                print(f"[INFO] Correlation Rule 就绪: {rule_id}")
            else:
                print(f"[WARNING] Correlation Rule 创建失败: {rule_result.get('message')}")
        
        # Step 3: 查询 Correlation 结果
        # 优先使用 OpenSearch Security Analytics API，如果不支持则回退到手动应用
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=time_window_minutes)
        
        # 注意：OpenSearch Security Analytics API 的 correlation 功能可能只在 raw-findings-* 索引中查找
        # 但我们的 correlation rule 配置的是在 ecs-events-* 索引中匹配 events
        # 因此需要强制使用手动应用规则模式，直接在 events 索引中查询
        correlations = query_correlation_results(
            start_time=start_time,
            end_time=end_time,
            rule_id=rule_id,
            limit=100,
            use_opensearch_api=False  # 强制使用手动应用规则模式（在 events 索引中查询）
        )
        
        print(f"[INFO] 找到 {len(correlations)} 个 Correlation 结果")
        
        if len(correlations) == 0:
            return {
                "correlations_found": 0,
                "chains_aggregated": 0,
                "findings_generated": 0,
                "errors": 0
            }
        
        # Step 4: 聚合关联链（基于 events）
        chains = aggregate_correlation_chains(correlations)
        print(f"[INFO] 聚合了 {len(chains)} 个攻击链（基于 events）")
        
        if len(chains) == 0:
            return {
                "correlations_found": len(correlations),
                "chains_aggregated": 0,
                "findings_generated": 0,
                "errors": 0
            }
        
        # Step 5: 生成高层事件并写入
        findings_to_index = []
        errors = 0
        
        for chain in chains:
            try:
                finding = generate_lateral_movement_finding(chain)
                findings_to_index.append({
                    "id": finding.get("event", {}).get("id"),
                    "document": finding
                })
            except Exception as e:
                print(f"[ERROR] 生成 Finding 失败: {e}")
                errors += 1
                continue
        
        # Step 6: 批量写入 Raw Findings
        if len(findings_to_index) > 0:
            result = bulk_index(raw_index_name, findings_to_index)
            if result.get("success", 0) > 0:
                refresh_index(raw_index_name)
                print(f"[INFO] 成功写入 {result.get('success', 0)} 个横向移动 Finding")
            
            return {
                "correlations_found": len(correlations),
                "chains_aggregated": len(chains),
                "findings_generated": result.get("success", 0),
                "errors": errors + result.get("failed", 0)
            }
        
        return {
            "correlations_found": len(correlations),
            "chains_aggregated": len(chains),
            "findings_generated": 0,
            "errors": errors
        }
        
    except Exception as e:
        print(f"[ERROR] Correlation 分析失败: {e}")
        import traceback
        traceback.print_exc()
        return {
            "correlations_found": 0,
            "chains_aggregated": 0,
            "findings_generated": 0,
            "errors": 1
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
            create_rule_if_not_exists=True
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
