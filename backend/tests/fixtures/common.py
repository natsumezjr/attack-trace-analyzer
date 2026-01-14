# -*- coding: utf-8 -*-
"""
测试工具和辅助函数
用于单元测试和系统测试
"""

from datetime import datetime
from typing import Any


def create_test_event(
    event_id: str,
    kind: str = "event",
    host_id: str = "h-test-001",
    host_name: str = "test-host",
    user_name: str = "testuser",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """
    创建测试事件数据（ECS 格式）
    
    Args:
        event_id: 事件唯一标识
        kind: 事件类型（event/alert）
        host_id: 主机ID
        host_name: 主机名
        user_name: 用户名
        timestamp: 时间戳（ISO格式），如果为None则使用当前时间
    
    Returns:
        符合ECS格式的事件字典
    """
    if timestamp is None:
        timestamp = datetime.now().isoformat()
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp,
        "event": {
            "id": event_id,
            "kind": kind,
            "created": timestamp,
            "ingested": timestamp,
            "category": ["authentication"] if kind == "event" else ["intrusion_detection"],
            "type": ["start"] if kind == "event" else ["alert"],
            "action": "user_login" if kind == "event" else "suspicious_activity",
            "dataset": "hostlog.auth" if kind == "event" else "finding.raw.falco",
        },
        "host": {
            "id": host_id,
            "name": host_name,
        },
        "user": {
            "name": user_name,
        },
        "source": {
            "ip": "10.0.0.1",
        },
        "message": f"测试事件: {event_id}",
    }


def create_test_finding(
    finding_id: str,
    technique_id: str = "T1078",
    tactic_id: str = "TA0001",
    severity: int = 70,
    provider: str = "falco",
    host_id: str = "h-test-001",
    host_name: str = "test-host",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """
    创建测试告警数据（Raw Finding）
    
    Args:
        finding_id: 告警唯一标识
        technique_id: ATT&CK技术ID
        tactic_id: ATT&CK战术ID
        severity: 严重程度（0-100）
        provider: 告警来源
        host_id: 主机ID
        host_name: 主机名
        timestamp: 时间戳（ISO格式），如果为None则使用当前时间
    
    Returns:
        符合Finding格式的告警字典
    """
    if timestamp is None:
        timestamp = datetime.now().isoformat()
    
    return {
        "ecs": {"version": "9.2.0"},
        "@timestamp": timestamp,
        "event": {
            "id": finding_id,
            "kind": "alert",
            "created": timestamp,
            "ingested": timestamp,
            "category": ["intrusion_detection"],
            "type": ["alert"],
            "action": "suspicious_activity",
            "dataset": f"finding.raw.{provider}",
            "severity": severity,
        },
        "rule": {
            "id": f"rule-{finding_id}",
            "name": "测试规则",
            "version": "1.0",
        },
        "threat": {
            "tactic": {
                "id": tactic_id,
                "name": "Initial Access",
            },
            "technique": {
                "id": technique_id,
                "name": "Valid Accounts",
            },
        },
        "custom": {
            "finding": {
                "stage": "raw",
                "providers": [provider],
            },
            "confidence": 0.8,
        },
        "host": {
            "id": host_id,
            "name": host_name,
        },
        "message": f"测试告警: {finding_id}",
    }


def create_test_finding_with_process(
    finding_id: str,
    process_entity_id: str = "proc-001",
    technique_id: str = "T1055",
    **kwargs
) -> dict[str, Any]:
    """
    创建带进程信息的测试告警
    
    Args:
        finding_id: 告警唯一标识
        process_entity_id: 进程实体ID
        technique_id: ATT&CK技术ID
        **kwargs: 其他参数传递给create_test_finding
    
    Returns:
        包含进程信息的告警字典
    """
    finding = create_test_finding(finding_id, technique_id=technique_id, **kwargs)
    finding["process"] = {
        "entity_id": process_entity_id,
        "pid": 1234,
        "name": "test.exe",
    }
    return finding


def create_test_finding_with_destination(
    finding_id: str,
    dst_ip: str = "192.168.1.100",
    dst_domain: str | None = None,
    technique_id: str = "T1071",
    **kwargs
) -> dict[str, Any]:
    """
    创建带目标IP/域名的测试告警
    
    Args:
        finding_id: 告警唯一标识
        dst_ip: 目标IP
        dst_domain: 目标域名（可选）
        technique_id: ATT&CK技术ID
        **kwargs: 其他参数传递给create_test_finding
    
    Returns:
        包含目标信息的告警字典
    """
    finding = create_test_finding(finding_id, technique_id=technique_id, **kwargs)
    finding["destination"] = {
        "ip": dst_ip,
        "port": 443,
    }
    if dst_domain:
        finding["destination"]["domain"] = dst_domain
    return finding


def create_test_finding_with_file(
    finding_id: str,
    file_hash: str = "abc123def456",
    file_path: str = "/tmp/test.exe",
    technique_id: str = "T1105",
    **kwargs
) -> dict[str, Any]:
    """
    创建带文件信息的测试告警
    
    Args:
        finding_id: 告警唯一标识
        file_hash: 文件SHA256哈希
        file_path: 文件路径
        technique_id: ATT&CK技术ID
        **kwargs: 其他参数传递给create_test_finding
    
    Returns:
        包含文件信息的告警字典
    """
    finding = create_test_finding(finding_id, technique_id=technique_id, **kwargs)
    finding["file"] = {
        "path": file_path,
        "hash": {
            "sha256": file_hash,
        },
    }
    return finding


def assert_event_structure(event: dict[str, Any], required_fields: list[str] | None = None):
    """
    断言事件结构是否符合ECS格式
    
    Args:
        event: 事件字典
        required_fields: 必需字段列表，如果为None则使用默认列表
    """
    if required_fields is None:
        required_fields = [
            "@timestamp",
            "ecs.version",
            "event.id",
            "event.kind",
            "host.id",
            "host.name",
        ]
    
    for field in required_fields:
        keys = field.split(".")
        value = event
        for key in keys:
            assert key in value, f"缺少必需字段: {field}"
            value = value[key]
        assert value is not None, f"字段 {field} 的值不能为None"


def assert_finding_structure(finding: dict[str, Any], stage: str = "raw"):
    """
    断言告警结构是否符合Finding格式
    
    Args:
        finding: 告警字典
        stage: 告警阶段（raw/canonical）
    """
    assert "@timestamp" in finding
    assert "event" in finding
    assert finding["event"]["kind"] == "alert"
    assert "custom" in finding
    assert "finding" in finding["custom"]
    assert finding["custom"]["finding"]["stage"] == stage
    assert "threat" in finding
    assert "technique" in finding["threat"]
    assert "id" in finding["threat"]["technique"]
