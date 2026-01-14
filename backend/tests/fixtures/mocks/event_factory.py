# -*- coding: utf-8 -*-
"""
事件数据工厂
用于生成测试用的事件数据
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


class EventFactory:
    """事件数据生成器"""

    @staticmethod
    def create_base_event(**kwargs) -> dict[str, Any]:
        """创建基础事件"""
        return {
            "@timestamp": kwargs.get("timestamp", datetime.now().isoformat()),
            "event": {
                "id": kwargs.get("event_id", "test-event-001"),
                "kind": kwargs.get("kind", "event"),
                "dataset": kwargs.get("dataset", "falco"),
            },
            "host": {
                "id": kwargs.get("host_id", "test-host-001"),
                "name": kwargs.get("host_name", "test-host"),
                "hostname": kwargs.get("hostname", "test-host.example.com"),
            },
            "process": {
                "entity_id": kwargs.get("process_id", "test-process-001"),
                "name": kwargs.get("process_name", "test-process"),
                "executable": kwargs.get("executable", "/bin/test"),
                "pid": kwargs.get("pid", 1234),
            }
        }

    @staticmethod
    def create_falco_event(**kwargs) -> dict[str, Any]:
        """创建Falco事件"""
        event = EventFactory.create_base_event(**kwargs)
        event["event"]["dataset"] = "falco"
        event["falco"] = {
            "rule": kwargs.get("rule", "Test rule"),
            "output": kwargs.get("output", "Test output"),
            "priority": kwargs.get("priority", "Info"),
        }
        return event

    @staticmethod
    def create_suricata_event(**kwargs) -> dict[str, Any]:
        """创建Suricata事件"""
        event = EventFactory.create_base_event(**kwargs)
        event["event"]["dataset"] = "suricata"
        event["suricata"] = {
            "alert": {
                "signature": kwargs.get("signature", "Test alert"),
                "severity": kwargs.get("severity", 1),
                "category": kwargs.get("category", "Test"),
            }
        }
        return event

    @staticmethod
    def create_filebeat_event(**kwargs) -> dict[str, Any]:
        """创建Filebeat事件"""
        event = EventFactory.create_base_event(**kwargs)
        event["event"]["dataset"] = "filebeat"
        event["filebeat"] = {
            "module": kwargs.get("module", "system"),
        }
        return event
