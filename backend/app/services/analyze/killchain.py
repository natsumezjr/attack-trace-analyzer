from __future__ import annotations

"""
KillChain Pipeline (Phase A -> Phase B -> Phase C -> Phase D/E)

Phase A:
  - 调用 behavior_state_machine(abnormal_edges) 得到 FSAGraph 列表（只含关键异常边）

Phase B:
  - 对每个 FSAGraph 的相邻段锚点，枚举候选通路（软剪枝 + 多级枚举 + 缓存）
  - 任意相邻锚点之间无联通候选 => 直接丢弃该 FSAGraph
  - 输出 SemanticCandidateSubgraph 列表（供 LLM 选择）

Phase C:
  - LLM 在全链一致性视角下，选择每个锚点对的一条候选通路，并返回解释文本
  - 当前提供可替换的 stub（mock 选择规则），你们可接真实 LLM

Phase D/E:
  - 特征向量提取 / TTP 比对，按要求留白 pass

存储要求：
  - killchain 结果仅存数据库：只需给 GraphNode / GraphEdge 的 props 写入 killchain uuid
  - ECS 合规：写入 custom.killchain.uuid
"""

import uuid
from collections import deque
from dataclasses import dataclass, field
from hashlib import sha1
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .attack_fsa import AttackState, FSAGraph, behavior_state_machine
from ..neo4j import db as graph_api
from ..neo4j.models import GraphEdge, GraphNode, NodeType, RelType, parse_uid
from ..neo4j.utils import _parse_ts_to_float


# ---------------------------------------------------------------------------
# Config knobs (Phase B)
# ---------------------------------------------------------------------------

TIME_MARGIN_SEC: float = 1.0
"""锚点窗口左右扩展的 margin（秒）：抗时钟偏差/入库延迟。"""

TIME_SKEW_TOLERANCE_SEC: float = 0.0
"""路径内时间单调约束的容忍（秒）；默认 0。"""

FIRST_K: int = 10
"""多级枚举：第一轮最多保留的候选路径数。"""

SECOND_K: int = 25
"""多级枚举：第二轮最多保留的候选路径数（更松/更大）。"""

MAX_PATHS_PER_PAIR: int = 20
"""每对锚点最终给 LLM 的候选路径数上限（控 token + 控时延）。"""

MAX_HOPS_DEFAULT: int = 8
"""默认最大 hop 数（路径边数）。"""

MAX_HOPS_BY_STATE: Dict[AttackState, int] = {
    # 扫描/发现类一般路径更长，允许更大 hop
    AttackState.RECONNAISSANCE: 10,
    AttackState.DISCOVERY: 10,
    AttackState.LATERAL_MOVEMENT: 10,
    # C2 通常较短
    AttackState.COMMAND_AND_CONTROL: 6,
    # 其它默认
}
"""按段状态动态设置 max_hops（不做节点类型限制，按你的决策）。"""

ALLOWED_RELTYPES: Tuple[RelType, ...] = (
    RelType.SPAWN,
    RelType.LOGON,
    RelType.RUNS_ON,
    RelType.FILE_ACCESS,
    RelType.NET_CONNECT,
    RelType.DNS_QUERY,
    RelType.RESOLVES_TO,
    RelType.HAS_IP,
)
"""Phase B 枚举通路时允许的关系类型白名单（减少噪声与爆炸）。"""

MAX_CACHE_ITEMS: int = 300
"""锚点候选缓存最大条目数（简化 FIFO 淘汰）。"""


# ---------------------------------------------------------------------------
# Helpers: ECS field access & stable ids
# ---------------------------------------------------------------------------

def _sha1_hex(raw: str, n: int = 16) -> str:
    """sha1 截断：用于生成稳定 id（path_id/edge_id）。"""
    return sha1(raw.encode("utf-8")).hexdigest()[:n]


def _ecs_get(props: Mapping[str, Any], dotted: str) -> Any:
    """
    获取 ECS 字段值：
    - 支持扁平键（"process.entity_id"）
    - 支持嵌套对象（{"process": {"entity_id": ...}}）
    """
    if dotted in props:
        return props.get(dotted)

    cur: Any = props
    for part in dotted.split("."):
        if not isinstance(cur, Mapping):
            return None
        if part not in cur:
            return None
        cur = cur[part]
    return cur


def _truncate(v: Any, max_len: int = 200) -> Any:
    """截断长字符串，避免 LLM 输入爆 token。"""
    if isinstance(v, str) and len(v) > max_len:
        return v[:max_len] + "…"
    return v


def _edge_ts(edge: GraphEdge) -> float:
    """统一边时间戳（float），用于排序/单调约束。"""
    raw = edge.get_ts()
    return _parse_ts_to_float(raw)


def _normalize_reltypes(reltypes: Sequence[Any]) -> Set[str]:
    """
    将 RelType/str 统一为 set[str]（RelType.value）。
    这样无论 API 期望传 RelType 还是 str，内部都能一致比较。
    """
    out: Set[str] = set()
    for rt in reltypes:
        if isinstance(rt, RelType):
            out.add(rt.value)
        elif isinstance(rt, str):
            out.add(rt)
        else:
            out.add(str(rt))
    return out


def _edge_stable_id(edge: GraphEdge) -> str:
    """
    为边生成稳定 id（用于引用/trace/LLM解释）。
    优先使用 ECS event.id（如存在），否则退化到 (src,dst,rtype,ts)。
    """
    eid = _ecs_get(edge.props, "event.id")
    if isinstance(eid, str) and eid:
        return eid
    raw = f"{edge.src_uid}|{edge.rtype.value}|{edge.dst_uid}|{edge.get_ts()}"
    return "e-" + _sha1_hex(raw)


# ---------------------------------------------------------------------------
# Data structures for Phase B/C
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PathStepView:
    """
    LLM 输入用的路径一步摘要（结构化、轻量）。
    """
    ts: float
    src_uid: str
    rel: str
    dst_uid: str
    key_props: Dict[str, Any]  # 白名单字段（截断）


@dataclass(frozen=True, slots=True)
class CandidatePath:
    """
    锚点之间的一条候选通路（用于 Phase C 选择）。

    注意：
    - edges: 原始 GraphEdge，用于回溯/落库标注
    - steps: LLM 输入摘要（强控字段、可比较）
    - signature: 用于去重（uid/rtype 序列 hash）
    """
    path_id: str
    src_anchor: str
    dst_anchor: str
    t_min: float
    t_max: float
    edges: Tuple[GraphEdge, ...]
    steps: Tuple[PathStepView, ...]
    signature: str


@dataclass(slots=True)
class SegmentSummary:
    """
    段摘要（段内不做连通重建；直接将段内异常边摘要给 LLM 做语义一致性判断）。
    """
    seg_idx: int
    state: str
    t_start: float
    t_end: float
    anchor_in_uid: str
    anchor_out_uid: str
    abnormal_edge_summaries: List[Dict[str, Any]]  # 段内 topN 异常边摘要


@dataclass(slots=True)
class AnchorPairCandidates:
    """
    相邻段锚点对的候选通路集合。
    任意 pair candidates 为空 => 丢弃该图。
    """
    pair_idx: int
    from_seg_idx: int
    to_seg_idx: int
    src_anchor: str
    dst_anchor: str
    t_min: float
    t_max: float
    candidates: List[CandidatePath]
    dropped_reason: Optional[str] = None


@dataclass(slots=True)
class SemanticCandidateSubgraph:
    """
    Phase B 输出：一个 FSA 图对应的“语义候选子图容器”（还未选路）。
    """
    fsa_graph: FSAGraph
    segments: List[SegmentSummary]
    pair_candidates: List[AnchorPairCandidates]
    trace: List[Dict[str, Any]] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class KillChain:
    """
    Phase C 输出：最终选出的 killchain（全链一致性）。
    """
    kc_uuid: str
    fsa_graph: FSAGraph
    segments: List[SegmentSummary]
    selected_paths: List[CandidatePath]
    explanation: str
    trace: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cache: anchor pair -> candidate paths
# ---------------------------------------------------------------------------

class AnchorPairCache:
    """
    锚点候选通路缓存：
      key = (src, dst, t_min_rounded, t_max_rounded, constraints_sig)
      value = List[CandidatePath]

    简化策略：FIFO 淘汰（够用且实现简单）。
    """

    def __init__(self, max_items: int = MAX_CACHE_ITEMS) -> None:
        self._max_items = max(1, int(max_items))
        self._store: Dict[Tuple[Any, ...], List[CandidatePath]] = {}
        self._order: Deque[Tuple[Any, ...]] = deque()

    def get(self, key: Tuple[Any, ...]) -> Optional[List[CandidatePath]]:
        return self._store.get(key)

    def set(self, key: Tuple[Any, ...], value: List[CandidatePath]) -> None:
        if key in self._store:
            self._store[key] = value
            return
        self._store[key] = value
        self._order.append(key)
        while len(self._order) > self._max_items:
            old = self._order.popleft()
            self._store.pop(old, None)


def _constraints_sig(
    allowed_reltypes: Sequence[Any],
    max_hops: int,
    k_limit: int,
    margin_sec: float,
) -> str:
    """生成缓存约束签名：同约束下可复用候选集。"""
    rels = sorted(_normalize_reltypes(allowed_reltypes))
    raw = f"rels={','.join(rels)}|h={max_hops}|k={k_limit}|m={margin_sec}"
    return _sha1_hex(raw)


# ---------------------------------------------------------------------------
# Segment summaries (for LLM global consistency)
# ---------------------------------------------------------------------------

EDGE_SUMMARY_KEYS: Tuple[str, ...] = (
    # event/core
    "event.id",
    "event.kind",
    "event.dataset",
    "event.action",
    "event.category",
    "event.type",
    "event.outcome",
    "event.severity",
    "message",
    # rule/finding
    "rule.id",
    "rule.name",
    # MITRE
    "threat.framework",
    "threat.tactic.id",
    "threat.tactic.name",
    "threat.technique.id",
    "threat.technique.name",
    # host/user/process/file/network/dns
    "host.id",
    "host.name",
    "user.id",
    "user.name",
    "process.entity_id",
    "process.pid",
    "process.name",
    "process.executable",
    "process.command_line",
    "file.path",
    "source.ip",
    "destination.ip",
    "source.port",
    "destination.port",
    "network.transport",
    "network.protocol",
    "dns.question.name",
    "domain.name",
    "ip",
)

def _summarize_edge(edge: GraphEdge, *, max_str_len: int = 200) -> Dict[str, Any]:
    """
    将单条边压缩为 LLM 友好的摘要 dict：
    - 保留 src/dst/rtype/ts
    - 按白名单抽取 ECS 字段（自动支持点号/嵌套）
    """
    out: Dict[str, Any] = {
        "edge_id": _edge_stable_id(edge),
        "ts": _edge_ts(edge),
        "src_uid": edge.src_uid,
        "dst_uid": edge.dst_uid,
        "rel": edge.rtype.value,
    }
    # 白名单字段抽取
    for k in EDGE_SUMMARY_KEYS:
        v = _ecs_get(edge.props, k)
        if v is None:
            continue
        out[k] = _truncate(v, max_len=max_str_len)
    return out


def build_segment_summaries(fsa_graph: FSAGraph, *, top_n: int = 6) -> List[SegmentSummary]:
    """
    从 fsa_graph.segments() 构造段摘要：
    - 段内不做连通重建，仅给 LLM 提供“段内异常边摘要集合”
    """
    segs = fsa_graph.segments()
    out: List[SegmentSummary] = []

    for idx, seg in enumerate(segs):
        # 取段内 key nodes（EdgeNode），转换成 GraphEdge
        edges: List[GraphEdge] = []
        for n in seg.nodes:
            if hasattr(n, "edge"):
                edges.append(n.edge)  # type: ignore[attr-defined]
            else:
                raise ValueError(f"EdgeNode has no edge attribute: {n}")

        # 段内摘要：选取 top_n 条“信息量较高”的边
        # 简化策略：
        #   - 先按时间排序
        #   - 做简单去重（同 edge_id 只保留一次）
        edges.sort(key=_edge_ts)
        seen: Set[str] = set()
        summaries: List[Dict[str, Any]] = []
        for e in edges:
            eid = _edge_stable_id(e)
            if eid in seen:
                continue
            seen.add(eid)
            summaries.append(_summarize_edge(e))
            if len(summaries) >= top_n:
                break

        out.append(
            SegmentSummary(
                seg_idx=idx,
                state=seg.state.value,
                t_start=seg.t_start,
                t_end=seg.t_end,
                anchor_in_uid=seg.anchor_in_uid,
                anchor_out_uid=seg.anchor_out_uid,
                abnormal_edge_summaries=summaries,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Phase B: enumerate candidate paths between anchors
# ---------------------------------------------------------------------------

def _max_hops_for_pair(a_state: str, b_state: str) -> int:
    """根据段状态选择 max_hops（不做节点类型限制，按你的决策）。"""
    try:
        a = AttackState(a_state)
        b = AttackState(b_state)
    except Exception:
        return MAX_HOPS_DEFAULT
    return max(MAX_HOPS_BY_STATE.get(a, MAX_HOPS_DEFAULT), MAX_HOPS_BY_STATE.get(b, MAX_HOPS_DEFAULT))


def _anchor_window(t_end: float, t_start: float, *, margin_sec: float = TIME_MARGIN_SEC) -> Tuple[float, float]:
    """
    时间剪枝窗口：
    - 基于你的假设（段间升序），锚点间只需要窗口 [seg.t_end, nxt.t_start]
    - 加 margin 抗偏差： [t_end - margin, t_start + margin]
    """
    return (t_end - margin_sec, t_start + margin_sec)


def _build_candidate_from_edges(
    src_anchor: str,
    dst_anchor: str,
    t_min: float,
    t_max: float,
    edges: Sequence[GraphEdge],
) -> CandidatePath:
    """将一条路径（edges序列）转为 CandidatePath（含 steps 摘要）。"""
    steps: List[PathStepView] = []
    for e in edges:
        steps.append(
            PathStepView(
                ts=_edge_ts(e),
                src_uid=e.src_uid,
                rel=e.rtype.value,
                dst_uid=e.dst_uid,
                key_props=_summarize_edge(e),  # 这里复用摘要（已控字段/截断）
            )
        )

    # signature：用 uid/rtype 序列去重
    sig_raw = "|".join(f"{e.src_uid}->{e.rtype.value}->{e.dst_uid}" for e in edges)
    signature = _sha1_hex(sig_raw, n=20)
    path_id = "p-" + _sha1_hex(f"{src_anchor}|{dst_anchor}|{t_min}|{t_max}|{signature}", n=16)

    return CandidatePath(
        path_id=path_id,
        src_anchor=src_anchor,
        dst_anchor=dst_anchor,
        t_min=t_min,
        t_max=t_max,
        edges=tuple(edges),
        steps=tuple(steps),
        signature=signature,
    )


def _get_edges_inter_nodes(
    *,
    t_min: float,
    t_max: float,
    allowed_reltypes: Sequence[Any]
) -> List[GraphEdge]:
    """
    查询两个 anchor 节点之间的边（返回边池，由调用方使用 _enumerate_paths_locally_bfs 枚举路径）。
    
    注意：max_hops 和 k 参数在此函数中不使用，因为路径枚举由调用方处理。
    本函数只负责获取 src_anchor 和 dst_anchor 之间的边池。
    我们认为，直接使用 get_edges_in_window 即可，按照时间顺序增长即为所有边。
    """
    # 使用底层 API 查询两个节点之间的边
    # graph_api.get_edges_inter_nodes 接受节点列表，查询这些节点之间的边
    edges = graph_api.get_edges_in_window(
        t_min=t_min,
        t_max=t_max,
    )
    
    # 过滤关系类型（如果底层 API 不支持，则在这里过滤）
    if allowed_reltypes:
        allowed = _normalize_reltypes(allowed_reltypes)
        edges = [e for e in edges if e.rtype.value in allowed]
    
    return edges


def _coerce_api_result_to_paths(res: Any) -> Optional[List[List[GraphEdge]]]:
    """
    适配 get_edges_inter_nodes 返回值形态：
    - 若返回 list[list[GraphEdge]] => 视为“路径集合”
    - 若返回其它类型 => None（表示需要用 edge_pool 本地枚举 or 无法处理）
    """
    if not isinstance(res, list) or not res:
        return []
    first = res[0]
    if isinstance(first, (list, tuple)):
        # 形如 [[GraphEdge,...], [GraphEdge,...]]
        if not first:
            return []
        if isinstance(first[0], GraphEdge):
            return [list(p) for p in res]
    return None


def _coerce_api_result_to_edge_pool(res: Any) -> Optional[List[GraphEdge]]:
    """
    适配 get_edges_inter_nodes 返回值形态：
    - 若返回 list[GraphEdge] => 视为“边池”（需要本地 BFS 枚举路径）
    """
    if not isinstance(res, list) or not res:
        return []
    if isinstance(res[0], GraphEdge):
        return list(res)
    return None


def _is_time_monotonic(edges: Sequence[GraphEdge], *, tolerance: float = TIME_SKEW_TOLERANCE_SEC) -> bool:
    """检查路径边序列时间是否单调不减（允许 tolerance）。"""
    last: Optional[float] = None
    for e in edges:
        ts = _edge_ts(e)
        if last is not None and ts + tolerance < last:
            return False
        last = ts
    return True


def _dedup_paths(paths: List[CandidatePath], *, limit: int) -> List[CandidatePath]:
    """
    去重 + 截断：
    - 去重 key = signature
    - 保持原顺序（更易调试）
    """
    out: List[CandidatePath] = []
    seen: Set[str] = set()
    for p in paths:
        if p.signature in seen:
            continue
        seen.add(p.signature)
        out.append(p)
        if len(out) >= limit:
            break
    return out


def _enumerate_paths_locally_bfs(
    edge_pool: Sequence[GraphEdge],
    *,
    src_anchor: str,
    dst_anchor: str,
    t_min: float,
    t_max: float,
    allowed_reltypes: Sequence[Any],
    max_hops: int,
    k_limit: int,
) -> List[List[GraphEdge]]:
    """
    使用“边池”在本地枚举路径（BFS，限制 hop 数，限制数量 k_limit）。

    说明：
    - 为了鲁棒性，我们将图视为“可无向连通”（即既可沿 edge.src->dst，也可反向走），
      这样不会因为方向定义差异导致断链。
    - 但最终 CandidatePath.steps 仍会展示 edge 的原始 src/dst。
    """
    allowed = _normalize_reltypes(allowed_reltypes)

    # 构建无向邻接：uid -> list[(neighbor_uid, edge)]
    adj: Dict[str, List[Tuple[str, GraphEdge]]] = {}
    for e in edge_pool:
        if e.rtype.value not in allowed:
            continue
        ts = _edge_ts(e)
        # 再次确保边在窗口内（防御式）
        if ts < t_min or ts > t_max:
            continue
        adj.setdefault(e.src_uid, []).append((e.dst_uid, e))
        adj.setdefault(e.dst_uid, []).append((e.src_uid, e))

    if src_anchor not in adj or dst_anchor not in adj:
        return []

    # BFS 状态：(current_uid, path_edges, visited_uids, last_ts)
    queue: Deque[Tuple[str, List[GraphEdge], Set[str], float]] = deque()
    queue.append((src_anchor, [], {src_anchor}, t_min))

    found: List[List[GraphEdge]] = []

    while queue and len(found) < k_limit:
        cur_uid, path_edges, visited, last_ts = queue.popleft()

        # hop 限制
        if len(path_edges) >= max_hops:
            continue

        for nxt_uid, edge in adj.get(cur_uid, []):
            if nxt_uid in visited:
                continue

            ts = _edge_ts(edge)
            # 路径时间单调（相对 last_ts）
            if ts + TIME_SKEW_TOLERANCE_SEC < last_ts:
                continue

            new_edges = path_edges + [edge]
            # 若到达 dst，记录
            if nxt_uid == dst_anchor:
                if _is_time_monotonic(new_edges):
                    found.append(new_edges)
                continue

            new_visited = set(visited)
            new_visited.add(nxt_uid)
            queue.append((nxt_uid, new_edges, new_visited, ts))

    return found


def enumerate_candidate_paths_multi_stage(
    *,
    cache: AnchorPairCache,
    src_anchor: str,
    dst_anchor: str,
    t_min: float,
    t_max: float,
    allowed_reltypes: Sequence[Any],
    max_hops: int,
) -> List[CandidatePath]:
    """
    多级枚举 + 缓存：
    Stage1: (max_hops, FIRST_K)
    Stage2: (max_hops+2, SECOND_K) 仅在 Stage1 无结果时触发
    """
    # ---------- Stage 1 ----------
    sig1 = _constraints_sig(allowed_reltypes, max_hops=max_hops, k_limit=FIRST_K, margin_sec=TIME_MARGIN_SEC)
    key1 = (src_anchor, dst_anchor, round(t_min, 3), round(t_max, 3), sig1)
    cached = cache.get(key1)
    if cached is not None:
        return _dedup_paths(cached, limit=MAX_PATHS_PER_PAIR)

    res = _get_edges_inter_nodes(
        t_min=t_min,
        t_max=t_max,
        allowed_reltypes=allowed_reltypes
    )

    # API 可能返回“路径集合”或“边池”
    paths = _coerce_api_result_to_paths(res)
    if paths is None:
        edge_pool = _coerce_api_result_to_edge_pool(res)
        if edge_pool is None:
            paths = []
        else:
            paths = _enumerate_paths_locally_bfs(
                edge_pool,
                src_anchor=src_anchor,
                dst_anchor=dst_anchor,
                t_min=t_min,
                t_max=t_max,
                allowed_reltypes=allowed_reltypes,
                max_hops=max_hops,
                k_limit=FIRST_K,
            )

    cand1 = [_build_candidate_from_edges(src_anchor, dst_anchor, t_min, t_max, p) for p in paths]
    cand1 = _dedup_paths(cand1, limit=MAX_PATHS_PER_PAIR)
    cache.set(key1, cand1)

    if cand1:
        return cand1

    # ---------- Stage 2 (only if empty) ----------
    max_hops2 = max_hops + 2
    sig2 = _constraints_sig(allowed_reltypes, max_hops=max_hops2, k_limit=SECOND_K, margin_sec=TIME_MARGIN_SEC)
    key2 = (src_anchor, dst_anchor, round(t_min, 3), round(t_max, 3), sig2)
    cached2 = cache.get(key2)
    if cached2 is not None:
        return _dedup_paths(cached2, limit=MAX_PATHS_PER_PAIR)

    res2 = _get_edges_inter_nodes(
        t_min=t_min,
        t_max=t_max,
        allowed_reltypes=allowed_reltypes
    )

    paths2 = _coerce_api_result_to_paths(res2)
    if paths2 is None:
        edge_pool2 = _coerce_api_result_to_edge_pool(res2)
        if edge_pool2 is None:
            paths2 = []
        else:
            paths2 = _enumerate_paths_locally_bfs(
                edge_pool2,
                src_anchor=src_anchor,
                dst_anchor=dst_anchor,
                t_min=t_min,
                t_max=t_max,
                allowed_reltypes=allowed_reltypes,
                max_hops=max_hops2,
                k_limit=SECOND_K,
            )

    cand2 = [_build_candidate_from_edges(src_anchor, dst_anchor, t_min, t_max, p) for p in paths2]
    cand2 = _dedup_paths(cand2, limit=MAX_PATHS_PER_PAIR)
    cache.set(key2, cand2)
    return cand2


def connect_fsa_segments_to_candidates(
    fsa_graph: FSAGraph,
    *,
    cache: AnchorPairCache,
    allowed_reltypes: Sequence[Any] = ALLOWED_RELTYPES,
) -> Optional[SemanticCandidateSubgraph]:
    """
    Phase B：连接所有相邻段锚点，生成候选通路集合。
    - 任意相邻锚点无候选 => return None（丢弃该图）
    """
    segments = build_segment_summaries(fsa_graph)

    # 只有 0/1 段无需连接，直接通过
    if len(segments) <= 1:
        return SemanticCandidateSubgraph(
            fsa_graph=fsa_graph,
            segments=segments,
            pair_candidates=[],
            trace=[{"phase": "B", "reason": "single_segment_or_empty"}],
            constraints={"allowed_reltypes": [rt.value if isinstance(rt, RelType) else str(rt) for rt in allowed_reltypes]},
        )

    pair_candidates: List[AnchorPairCandidates] = []
    trace: List[Dict[str, Any]] = []

    for i in range(len(segments) - 1):
        seg = segments[i]
        nxt = segments[i + 1]

        src_anchor = seg.anchor_out_uid
        dst_anchor = nxt.anchor_in_uid

        # 锚点不能为空
        if not src_anchor or not dst_anchor:
            trace.append({"phase": "B", "pair_idx": i, "reason": "empty_anchor", "src": src_anchor, "dst": dst_anchor})
            return None

        t_min, t_max = _anchor_window(seg.t_end, nxt.t_start, margin_sec=TIME_MARGIN_SEC)
        if t_min > t_max:
            trace.append({"phase": "B", "pair_idx": i, "reason": "invalid_time_window", "t_min": t_min, "t_max": t_max})
            return None

        max_hops = _max_hops_for_pair(seg.state, nxt.state)

        trace.append(
            {
                "phase": "B",
                "pair_idx": i,
                "from_state": seg.state,
                "to_state": nxt.state,
                "src_anchor": src_anchor,
                "dst_anchor": dst_anchor,
                "t_min": t_min,
                "t_max": t_max,
                "max_hops": max_hops,
            }
        )

        cands = enumerate_candidate_paths_multi_stage(
            cache=cache,
            src_anchor=src_anchor,
            dst_anchor=dst_anchor,
            t_min=t_min,
            t_max=t_max,
            allowed_reltypes=allowed_reltypes,
            max_hops=max_hops,
        )

        if not cands:
            trace.append({"phase": "B", "pair_idx": i, "reason": "no_path_candidates"})
            return None

        pair_candidates.append(
            AnchorPairCandidates(
                pair_idx=i,
                from_seg_idx=seg.seg_idx,
                to_seg_idx=nxt.seg_idx,
                src_anchor=src_anchor,
                dst_anchor=dst_anchor,
                t_min=t_min,
                t_max=t_max,
                candidates=cands,
                dropped_reason=None,
            )
        )

    return SemanticCandidateSubgraph(
        fsa_graph=fsa_graph,
        segments=segments,
        pair_candidates=pair_candidates,
        trace=trace,
        constraints={
            "time_margin_sec": TIME_MARGIN_SEC,
            "first_k": FIRST_K,
            "second_k": SECOND_K,
            "max_paths_per_pair": MAX_PATHS_PER_PAIR,
            "allowed_reltypes": [rt.value if isinstance(rt, RelType) else str(rt) for rt in allowed_reltypes],
        },
    )


def build_semantic_candidate_subgraphs(
    graphs: Sequence[FSAGraph],
    *,
    cache: Optional[AnchorPairCache] = None,
    allowed_reltypes: Sequence[Any] = ALLOWED_RELTYPES,
) -> List[SemanticCandidateSubgraph]:
    """对所有 FSAGraph 运行 Phase B，输出“可联通”的候选子图列表。"""
    cache = cache or AnchorPairCache()
    out: List[SemanticCandidateSubgraph] = []
    for g in graphs:
        cand = connect_fsa_segments_to_candidates(g, cache=cache, allowed_reltypes=allowed_reltypes)
        if cand is None:
            continue
        out.append(cand)
    return out


# ---------------------------------------------------------------------------
# Phase C: LLM global selection (stub/mock, replaceable)
# ---------------------------------------------------------------------------

def build_llm_payload(candidate: SemanticCandidateSubgraph) -> Dict[str, Any]:
    """
    给 LLM 的 payload：
    - segments：段内异常摘要（供语义一致性）
    - pairs：每对锚点候选路径（仅 steps 摘要 + path_id）
    注意：不传全量 props，只传白名单摘要 + 可回溯 id。
    """
    pairs_payload: List[Dict[str, Any]] = []
    for p in candidate.pair_candidates:
        pairs_payload.append(
            {
                "pair_idx": p.pair_idx,
                "from_seg_idx": p.from_seg_idx,
                "to_seg_idx": p.to_seg_idx,
                "src_anchor": p.src_anchor,
                "dst_anchor": p.dst_anchor,
                "t_min": p.t_min,
                "t_max": p.t_max,
                "candidates": [
                    {
                        "path_id": c.path_id,
                        "steps": [
                            {
                                "ts": s.ts,
                                "src_uid": s.src_uid,
                                "rel": s.rel,
                                "dst_uid": s.dst_uid,
                                # key_props 已是白名单/截断后的摘要
                                "key_props": s.key_props,
                            }
                            for s in c.steps
                        ],
                    }
                    for c in p.candidates
                ],
            }
        )

    return {
        "constraints": candidate.constraints,
        "segments": [
            {
                "seg_idx": s.seg_idx,
                "state": s.state,
                "t_start": s.t_start,
                "t_end": s.t_end,
                "anchor_in_uid": s.anchor_in_uid,
                "anchor_out_uid": s.anchor_out_uid,
                "abnormal_edge_summaries": s.abnormal_edge_summaries,
            }
            for s in candidate.segments
        ],
        "pairs": pairs_payload,
    }


def select_killchain_with_llm(
    candidate: SemanticCandidateSubgraph,
    *,
    llm_client: Any = None,
) -> KillChain:
    """
    Phase C：LLM 选择全链最可能路径。

    你们接入真实 LLM 时建议约定 llm_client 接口：
      llm_client.choose(payload: dict) -> dict:
        {
          "chosen_path_ids": ["p-...", "p-...", ...],   # 顺序与 pairs 一致
          "explanation": "..."
        }

    当前 stub 策略（可跑通）：
      - 每个 pair 选择 hop 最短的一条（edges 数最少）
      - explanation 写入简单占位文本
    """
    payload = build_llm_payload(candidate)

    chosen_ids: List[str] = []
    explanation: str = ""

    if llm_client is not None and hasattr(llm_client, "choose"):
        res = llm_client.choose(payload)
        if isinstance(res, Mapping):
            ids = res.get("chosen_path_ids")
            if isinstance(ids, list) and all(isinstance(x, str) for x in ids):
                chosen_ids = list(ids)
            exp = res.get("explanation")
            if isinstance(exp, str):
                explanation = exp

    # fallback：最短 hop
    if not chosen_ids:
        for p in candidate.pair_candidates:
            best = min(p.candidates, key=lambda c: len(c.edges))
            chosen_ids.append(best.path_id)
        explanation = "mock: selected shortest-hop path per anchor pair (replace with LLM)."

    killchain = materialize_killchain(candidate, chosen_ids, explanation=explanation)
    return killchain


def materialize_killchain(
    candidate: SemanticCandidateSubgraph,
    chosen_path_ids: Sequence[str],
    *,
    explanation: str,
) -> KillChain:
    """把 LLM 输出的 path_id 列表映射回 CandidatePath，生成最终 KillChain。"""
    # 建立 path_id -> CandidatePath 的索引
    idx: Dict[str, CandidatePath] = {}
    for p in candidate.pair_candidates:
        for c in p.candidates:
            idx[c.path_id] = c

    selected: List[CandidatePath] = []
    for pid in chosen_path_ids:
        c = idx.get(pid)
        if c is None:
            # 若 LLM 返回了不存在的 id，直接忽略（也可 raise，按你们偏好）
            continue
        selected.append(c)

    kc_uuid = str(uuid.uuid4())

    return KillChain(
        kc_uuid=kc_uuid,
        fsa_graph=candidate.fsa_graph,
        segments=candidate.segments,
        selected_paths=selected,
        explanation=explanation,
        trace=list(candidate.trace),
    )


# ---------------------------------------------------------------------------
# Persist: annotate edges/nodes with kc_uuid (ECS: custom.killchain.uuid)
# ---------------------------------------------------------------------------

KC_ECS_FIELD: str = "custom.killchain.uuid"
"""ECS 合规的 killchain uuid 字段（custom.* 命名空间）。"""


def _set_kc_uuid_on_edge(edge: GraphEdge, kc_uuid: str) -> None:
    """给边写入 killchain uuid（同时写入 props）。"""
    edge.props[KC_ECS_FIELD] = kc_uuid
    # 若 models 已新增 kc_uuid 字段，则同步赋值（best-effort）
    try:
        setattr(edge, "kc_uuid", kc_uuid)
    except Exception:
        pass


def _minimal_node_from_uid(uid: str, kc_uuid: str) -> Optional[GraphNode]:
    """
    用 uid 生成“最小 GraphNode”，仅用于把 custom.killchain.uuid merge 写入数据库。
    这样无需依赖 get_node API。
    """
    try:
        ntype, key = parse_uid(uid)
    except Exception:
        return None
    return GraphNode(ntype=ntype, key=key, props={KC_ECS_FIELD: kc_uuid})


def _set_kc_uuid_on_node(node: GraphNode, kc_uuid: str) -> None:
    """给节点写入 killchain uuid（props + best-effort 字段）。"""
    node.props[KC_ECS_FIELD] = kc_uuid
    try:
        setattr(node, "kc_uuid", kc_uuid)
    except Exception:
        pass


def persist_killchain_to_db(kc: KillChain) -> None:
    """
    将 killchain 结果落库（仅靠在 props 写 kc_uuid）：

    逻辑：
      1) 收集 killchain 涉及的边（FSA key edges + Phase C 选中的连接边）
      2) 对每条边写入 custom.killchain.uuid
      3) 对边涉及的节点 uid 生成最小 GraphNode，并写入 custom.killchain.uuid
      4) 调用 graph_api.add_edge / add_node 写入数据库（假设已实现 upsert/merge）

    注意：
      - 如果你们的 add_edge 仍然是 CREATE 关系，会产生重复边；
        建议你们的 DB 写入层对 edge 使用 event.id 或其它稳定键做 MERGE。
    """
    if not hasattr(graph_api, "add_edge") or not hasattr(graph_api, "add_node"):
        raise RuntimeError("graph_api.add_edge/add_node not found; cannot persist killchain.")

    add_edge = graph_api.add_edge
    add_node = graph_api.add_node

    kc_uuid = kc.kc_uuid

    # 1) 收集边（去重：按 stable edge id）
    edges: List[GraphEdge] = []
    seen_e: Set[str] = set()

    # 1.1 FSA key edges
    for n in getattr(kc.fsa_graph, "nodes", []):
        if hasattr(n, "edge"):
            e = n.edge  # type: ignore[attr-defined]
            eid = _edge_stable_id(e)
            if eid not in seen_e:
                seen_e.add(eid)
                edges.append(e)

    # 1.2 Phase C selected path edges
    for p in kc.selected_paths:
        for e in p.edges:
            eid = _edge_stable_id(e)
            if eid not in seen_e:
                seen_e.add(eid)
                edges.append(e)

    # 2) 写入边 props 并落库
    for e in edges:
        _set_kc_uuid_on_edge(e, kc_uuid)
        add_edge(e)

    # 3) 收集节点 uid（从边端点）
    node_uids: Set[str] = set()
    for e in edges:
        node_uids.add(e.src_uid)
        node_uids.add(e.dst_uid)

    # 4) 生成最小节点并 merge 写入
    for uid in node_uids:
        node = _minimal_node_from_uid(uid, kc_uuid)
        if node is None:
            continue
        _set_kc_uuid_on_node(node, kc_uuid)
        add_node(node)


# ---------------------------------------------------------------------------
# Phase D/E: stubs (leave blank as requested)
# ---------------------------------------------------------------------------

def extract_vectors_from_chain(killchain: KillChain) -> Any:
    """Phase D: 从最终 killchain 提取 TTP 特征向量（留白）。"""
    pass


def match_vector_features(vectors: Any) -> Any:
    """Phase E: 与现有 TTP 特征库比对（留白）。"""
    pass


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_killchain_pipeline(
    *,
    llm_client: Any = None,
    persist: bool = True,
) -> List[KillChain]:
    """
    完整流水线：
      abnormal -> PhaseA(FSA) -> PhaseB(candidate) -> PhaseC(LLM choose) -> persist kc_uuid -> return killchains
    """
    abnormal = graph_api.get_alarm_edges()

    # Phase A
    fsa_graphs = behavior_state_machine(abnormal)

    # Phase B
    cache = AnchorPairCache(max_items=MAX_CACHE_ITEMS)
    candidates = build_semantic_candidate_subgraphs(fsa_graphs, cache=cache)

    # Phase C
    killchains: List[KillChain] = []
    for cand in candidates:
        kc = select_killchain_with_llm(cand, llm_client=llm_client)
        killchains.append(kc)

        # Persist (kc_uuid -> props -> DB)
        if persist:
            persist_killchain_to_db(kc)

    # Phase D/E (left blank, but pipeline position preserved)
    # for kc in killchains:
    #     vectors = extract_vectors_from_chain(kc)
    #     match_res = match_vector_features(vectors)

    return killchains


if __name__ == "__main__":
    # 示例：使用 LLM client（如果配置了 OPENAI_API_KEY 环境变量）
    # 否则自动回退到 MockChooser
    try:
        from .killchain_llm import create_llm_client
        llm_client = create_llm_client()
    except Exception as e:
        print(f"[killchain] 无法创建 LLM client: {e}，使用 fallback")
        llm_client = None

    kcs = run_killchain_pipeline(llm_client=llm_client, persist=False)
    print(f"[killchain] produced killchains: {len(kcs)}")
    for i, kc in enumerate(kcs[:3]):
        print(f"--- kc #{i} ---")
        print(f"kc_uuid={kc.kc_uuid}")
        print(f"segments={len(kc.segments)} selected_paths={len(kc.selected_paths)}")
        print(f"explanation={kc.explanation[:120]}")
