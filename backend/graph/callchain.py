from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Tuple
from collections import defaultdict
from graph.models import GraphNode, GraphEdge, RelType

# ==========================================
# 中间态数据结构
# ==========================================

# 连通子图容器:先把要用的节点和边一次性拉到内存里，在内存里建立索引，实现快速查询（空间换时间）
@dataclass
class Subgraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    
    # 邻接表索引：加速查询
    # key: dst_uid, value: list[GraphEdge] (指向该节点的所有边，即入边)
    _incoming_index: dict[str, list[GraphEdge]] = field(default_factory=lambda: defaultdict(list))

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.uid] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        self._incoming_index[edge.dst_uid].append(edge)

    def get_node(self, uid: str) -> GraphNode | None:
        return self.nodes.get(uid)

    def get_incoming_edges(self, node_uid: str) -> list[GraphEdge]:
        """获取指向该节点的所有边 (用于回溯)"""
        return self._incoming_index[node_uid]

#    [重构后的KillChain] 纯数据类，只负责存储最终的攻击路径。
@dataclass
class CallChain:
    # 存储结构：直接存由边组成的有序列表，节点信息隐含在边中
    chain: list[GraphEdge] = field(default_factory=list)
    @property
    def length(self) -> int:
        return len(self.chain)


# ==========================================
# 分析流水线实现 (Pipeline Implementation)
# ==========================================

#### 1. 数据获取
def fetch_edges_from_db() -> tuple[list[GraphEdge], list[GraphEdge]]:
    return [], []

#### 2. 状态机 (构建初步子图)
def behavior_state_machine(
    normal_edges: list[GraphEdge], 
    abnormal_edges: list[GraphEdge]
) -> list[Subgraph]:
    """
    逻辑：根据时序和实体关联，将边聚合成一个个 Subgraph 对象。
    """
    subgraphs: list[Subgraph] = []
    
    # 示例逻辑
    for edge in abnormal_edges:
        sg = Subgraph()
        sg.add_edge(edge)
        # 注意：这里也需要 fetch 节点信息并 add_node，暂略
        subgraphs.append(sg)
        
    return subgraphs

#### 3. 子图补全
def expand_to_complete_subgraph(subgraph: Subgraph) -> Subgraph:
    """
    逻辑：拿到 subgraph 里的所有 node uid，去数据库查它们之间漏掉的边，
    加回到 subgraph 对象中，使其“完全连通”。
    """
    # 模拟：此处应该调用 database API 查找更多关联边
    # new_edges = db.find_edges_between(subgraph.nodes.keys())
    # for e in new_edges: subgraph.add_edge(e)
    return subgraph

#### 4. 溯源分析

# 辅助配置与工具

# 1. 基础威胁权重表 (Base Risk Weights)
BASE_RISK_WEIGHTS: dict[RelType, float] = {
    RelType.SPAWNED: 5.0,     # 进程衍生是核心
    RelType.CONNECTED: 4.0,   # C2通信
    RelType.LOGON: 3.0,       # 横向移动风险
    RelType.ACCESSED: 2.0,    # 文件读写
    RelType.RESOLVES_TO: 1.0, # 基础设施解析
    RelType.RESOLVED: 1.0,
}

DEFAULT_ALLOWED_RELTYPES: Tuple[str, ...] = tuple(BASE_RISK_WEIGHTS.keys())


def fetch_abnormal_edges_from_db() -> List[GraphEdge]:
    """abnormal-only：用 is_alarm=true 的边。"""
    return graph_api.get_alarm_edges()


def expand_complete(
    graphs: List[FSAGraph],
    *,
    allowed_reltypes: Sequence[str] = DEFAULT_ALLOWED_RELTYPES,
    min_risk: float = 1.0,
) -> List[FSAGraph]:
    """Phase B：按 state 聚合段间连接；窗口严格限定；失败整条丢弃。"""
    out: List[FSAGraph] = []
    allowed_reltypes = list(allowed_reltypes)

    for g in graphs:
        segs = g.segments()
        if len(segs) <= 1:
            out.append(g)
            continue

        new_nodes: List[Any] = []
        ok = True

        for idx, seg in enumerate(segs):
            new_nodes.extend(seg.nodes)

            if idx == len(segs) - 1:
                break

            nxt = segs[idx + 1]

            src_anchor = seg.anchor_out_uid
            dst_anchor = nxt.anchor_in_uid
            t_min = seg.t_end
            t_max = nxt.t_start

            g.trace.append(
                {
                    "phase": "B",
                    "segment_idx": idx,
                    "from_state": seg.state.value,
                    "to_state": nxt.state.value,
                    "src_anchor": src_anchor,
                    "dst_anchor": dst_anchor,
                    "t_min": t_min,
                    "t_max": t_max,
                }
            )

            if not src_anchor or not dst_anchor:
                ok = False
                g.trace.append({"phase": "B", "reason": "empty_anchor"})
                break

            if t_min > t_max:
                ok = False
                g.trace.append({"phase": "B", "reason": "invalid_time_window", "t_min": t_min, "t_max": t_max})
                break

            if src_anchor == dst_anchor:
                g.trace.append({"phase": "B", "reason": "trivial_anchor_same"})
                continue

            # 按你的话：窗口内无边 => 不可能有通路 => 直接丢弃
            window_edges = graph_api.get_edges_in_window(t_min, t_max, allowed_reltypes=allowed_reltypes)
            if not window_edges:
                ok = False
                g.trace.append({"phase": "B", "reason": "window_empty"})
                break

            res = graph_api.gds_shortest_path_in_window(
                src_anchor,
                dst_anchor,
                t_min,
                t_max,
                risk_weights=BASE_RISK_WEIGHTS,
                min_risk=min_risk,
                allowed_reltypes=allowed_reltypes,
            )

            if res is None:
                ok = False
                g.trace.append({"phase": "B", "reason": "no_path"})
                break

            total_cost, path_edges = res

            # 可选但推荐：校验路径时间单调性（不单调就当作无效）
            if not _is_time_monotonic(path_edges):
                ok = False
                g.trace.append({"phase": "B", "reason": "non_monotonic_time_in_path"})
                break

            for e in path_edges:
                new_nodes.append(KillChainEdgeNode(e, is_key=False, is_completion=True))

            g.trace.append(
                {
                    "phase": "B",
                    "segment_idx": idx,
                    "completion_edges": len(path_edges),
                    "total_cost": total_cost,
                }
            )

        if not ok:
            continue

        g.nodes = new_nodes
        out.append(g)

    return out


def _is_time_monotonic(edges: Sequence[GraphEdge], *, tolerance: float = 0.0) -> bool:
    last = None
    for e in edges:
        ts = _parse_ts_to_float(e.get_ts() if hasattr(e, "get_ts") else None)
        if last is not None and ts + tolerance < last:
            return False
        last = ts
    return True


def run_killchain_pipeline() -> List[FSAGraph]:
    """完整流程：abnormal -> PhaseA(FSA) -> PhaseB(GDS) -> FSAGraph list"""
    from backend.data.attack_fsa import behavior_state_machine

    abnormal = fetch_abnormal_edges_from_db()
    graphs = behavior_state_machine(abnormal)
    graphs = expand_complete(graphs)
    return graphs


if __name__ == "__main__":
    gs = run_killchain_pipeline()
    print(f"[killchain] completed graphs: {len(gs)}")
    for i, g in enumerate(gs[:5]):
        print(f"--- graph #{i} ---")
        print(f"nodes={len(g.nodes)} segments={len(g.segments())} t=[{g.t_start:.3f},{g.t_end:.3f}]")

