# -*- coding: utf-8 -*-
"""
图数据工厂
用于生成测试用的图节点和边数据
"""
from __future__ import annotations

from typing import Any


def _import_models():
    """延迟导入模型，避免循环依赖"""
    from app.services.neo4j.models import GraphNode, GraphEdge, NodeType, RelType
    return GraphNode, GraphEdge, NodeType, RelType


class GraphFactory:
    """图数据生成器"""

    @staticmethod
    def create_node(uid: str, ntype: str, **kwargs) -> Any:
        """创建图节点

        Args:
            uid: 节点唯一标识
            ntype: 节点类型字符串 (如 "Host", "Process", "File")
            **kwargs: 节点属性
        """
        GraphNode, NodeType = _import_models()[:2]

        # 转换字符串类型为枚举
        ntype_enum = NodeType(ntype)

        return GraphNode(
            uid=uid,
            ntype=ntype_enum,
            key=kwargs.get("key", {}),
            props=kwargs.get("props", {}),
        )

    @staticmethod
    def create_edge(src_uid: str, dst_uid: str, rtype: str, **kwargs) -> Any:
        """创建图边

        Args:
            src_uid: 源节点UID
            dst_uid: 目标节点UID
            rtype: 关系类型字符串 (如 "WROTE", "NET_CONNECT")
            **kwargs: 边属性
        """
        GraphEdge, RelType = _import_models()[0], _import_models()[3]

        # 转换字符串类型为枚举
        rtype_enum = RelType(rtype)

        return GraphEdge(
            src_uid=src_uid,
            dst_uid=dst_uid,
            rtype=rtype_enum,
            props=kwargs.get("props", {}),
        )

    @staticmethod
    def create_test_graph():
        """创建测试图（包含节点和边）"""
        nodes = [
            GraphFactory.create_node("Host:h-001", "Host", props={"host.id": "h-001"}),
            GraphFactory.create_node("Process:p-001", "Process", props={"process.entity_id": "p-001"}),
            GraphFactory.create_node("File:f-001", "File", props={"file.path": "/tmp/test"}),
        ]
        edges = [
            GraphFactory.create_edge(
                "Process:p-001",
                "File:f-001",
                "WROTE",
                props={
                    "event.id": "evt-001",
                    "ts_float": 1640995200.0
                }
            ),
        ]
        return nodes, edges
