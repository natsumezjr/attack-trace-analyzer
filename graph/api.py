# graph/api.py
# 定义与图相关的API接口，包括数据库的增删改查。
from models import GraphNode, GraphEdge, AlarmSubgraph
from typing import List, Tuple

def add_node(node: GraphNode):
    pass

def add_edge(edge: GraphEdge):
    pass

def get_edges(node: GraphNode) -> List[GraphEdge]:  # 获取某个节点的所有边
    pass

def get_node(uid: str) -> GraphNode:
    pass

def get_alarm_edges() -> List[GraphEdge]:  # 获取所有异常节点
    pass
                








