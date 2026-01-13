# OpenSearch 数据分析模块
# 包含 Security Analytics 检测调用和告警融合去重

import hashlib
from typing import Any
from datetime import datetime

from .client import get_client, search, bulk_index
from .index import INDEX_PATTERNS, get_index_name

# 时间窗口（分钟），用于时间桶计算
TIME_WINDOW_MINUTES = 3  # 实验规模小，建议偏小（1-5分钟）


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
    timestamp_str = finding.get("@timestamp") or finding.get("event", {}).get("created")
    if timestamp_str:
        if isinstance(timestamp_str, str):
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            timestamp = timestamp_str
    else:
        timestamp = datetime.now()

    timestamp_ms = int(timestamp.timestamp() * 1000)
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


def run_security_analytics() -> dict[str, Any]:
    """
    触发 OpenSearch Security Analytics 检测
    注意：这需要 Security Analytics 插件已配置好 detector 和规则
    对于 MVP，可以先返回模拟结果或调用实际的 OSA API
    """
    client = get_client()

    try:
        # TODO: 实现实际的 OpenSearch Security Analytics API 调用
        # 1. 列出所有 detectors
        # 2. 触发检测（如果支持手动触发）
        # 3. 等待检测完成
        # 4. 读取检测结果并写入 raw-findings-*

        # 临时实现：返回提示信息
        print("警告: OpenSearch Security Analytics 检测功能需要配置 detector 和规则")
        print("警告: 当前为 MVP 版本，建议先手动配置 Security Analytics，然后调用 deduplicate_findings")

        return {
            "success": True,
            "message": "Security Analytics 检测需要先配置 detector（当前为 MVP 版本）",
        }
    except Exception as error:
        print(f"Security Analytics 检测失败: {error}")
        return {
            "success": False,
            "message": str(error) if isinstance(error, Exception) else "检测失败",
        }


def run_data_analysis() -> dict[str, Any]:
    """
    数据分析主函数
    1. 运行 Security Analytics 检测（Store-first）
    2. 告警融合去重（Raw → Canonical）
    """
    # Step 1: 运行 Security Analytics 检测
    detection_result = run_security_analytics()

    # Step 2: 告警融合去重
    deduplication_result = deduplicate_findings()

    return {
        "detection": detection_result,
        "deduplication": deduplication_result,
    }
