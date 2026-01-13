from __future__ import annotations
from typing import Any, List, Sequence, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from backend.graph.models import GraphNode, GraphEdge, RelType
from backend.graph import api as graph_api
from backend.graph.utils import _parse_ts_to_float
from backend.data.attack_fsa import FSAGraph, KillChainEdgeNode

# 1. 基础威胁权重表 (Base Risk Weights)
BASE_RISK_WEIGHTS: dict[str, float] = {
    RelType.PARENT_OF.value: 5.0,   # 进程父子是核心
    RelType.CONNECTED.value: 4.0,   # C2 通信
    RelType.LOGON.value: 3.0,       # 横向移动风险
    RelType.USES.value: 2.0,        # 文件读写
    RelType.OWNS.value: 1.0,        # 归属关系
    RelType.RESOLVES_TO.value: 1.0, # 基础设施解析
    RelType.RESOLVED.value: 1.0,
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

