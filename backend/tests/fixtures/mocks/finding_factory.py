# -*- coding: utf-8 -*-
"""
告警数据工厂
用于生成测试用的告警数据
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


class FindingFactory:
    """告警数据生成器"""

    @staticmethod
    def create_raw_finding(**kwargs) -> dict[str, Any]:
        """创建原始告警"""
        return {
            "@timestamp": kwargs.get("timestamp", datetime.now().isoformat()),
            "event": {
                "id": kwargs.get("finding_id", "test-finding-001"),
                "kind": "alert",
                "dataset": kwargs.get("dataset", "finding.raw"),
            },
            "threat": {
                "technique": {
                    "id": kwargs.get("technique_id", "T1078"),
                    "name": kwargs.get("technique_name", "Valid Accounts"),
                    "reference": kwargs.get("reference", "https://attack.mitre.org/techniques/T1078")
                },
                "tactic": {
                    "id": kwargs.get("tactic_id", "TA0001"),
                    "name": kwargs.get("tactic_name", "Initial Access"),
                    "reference": kwargs.get("tactic_reference", "https://attack.mitre.org/tactics/TA0001")
                }
            },
            "host": {
                "id": kwargs.get("host_id", "test-host-001"),
                "name": kwargs.get("host_name", "test-host"),
            },
            "custom": {
                "finding": {
                    "stage": "raw",
                    "providers": kwargs.get("providers", ["falco"]),
                }
            }
        }

    @staticmethod
    def create_canonical_finding(**kwargs) -> dict[str, Any]:
        """创建规范告警"""
        finding = FindingFactory.create_raw_finding(**kwargs)
        finding["event"]["dataset"] = "finding.canonical"
        finding["custom"]["finding"]["stage"] = "canonical"
        return finding
