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

from .attack_fsa import AttackState, FSAGraph, StateSegment, behavior_state_machine
from ..neo4j import db as graph_api
from ..neo4j.models import GraphEdge, GraphNode, NodeType, RelType, parse_uid, _ntype_of
from ..neo4j.utils import _parse_ts_to_float
from .killchain_llm import KillChainLLMClient


# ----------------------------------------
# Unified logging functions
# ----------------------------------------
@dataclass
class DroppedFSAGraph:
    """记录被丢弃的 FSA 图及其断联信息"""
    fsa_graph: FSAGraph
    last_connected_state: Optional[str] = None  # 最后成功连接的状态
    failed_transition: Optional[Tuple[str, str]] = None  # 失败的转移 (from_state, to_state)


def _log_dropped_killchains(dropped: List[DroppedFSAGraph]) -> None:
    """
    统一的丢弃 killchain 日志输出函数。
    输出所有被丢弃的 killchain 已经联通的状态（即子 FSAGraph 状态，说明断联末状态）。
    """
    if not dropped:
        return
    
    print(f"[WARN] 共有 {len(dropped)} 个 FSAGraph 无法生成 killchain，已全部丢弃")
    for idx, item in enumerate(dropped):
        segments = item.fsa_graph.segments()
        segment_states = [seg.state.value for seg in segments]
        print(f"[WARN] 丢弃的 FSAGraph[{idx}]: 状态序列: {' -> '.join(segment_states)}")
        
        if item.last_connected_state:
            print(f"[WARN]   - 最后成功连接的状态: {item.last_connected_state}")
        if item.failed_transition:
            from_state, to_state = item.failed_transition
            print(f"[WARN]   - 断联位置: {from_state} -> {to_state} (无法找到连接路径)")


# ---------------------------------------------------------------------------
# Config knobs (Phase B)
# ---------------------------------------------------------------------------

KC_ECS_FIELD: str = "custom.killchain.uuid"
"""ECS 合规字段：killchain uuid 写入到 edge/node 的该字段。"""

TIME_MARGIN_SEC: float = 120.0
"""锚点窗口左右扩展的 margin（秒）：抗时钟偏差/入库延迟。测试数据跨度较大，放宽为 120 秒。"""

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
# Semantic anchor selection rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnchorSemanticRule:
    """锚点语义规则：定义哪些边适合作为锚点候选"""
    # 允许的关系类型列表（None表示不限制）
    allowed_reltypes: Optional[Set[RelType]] = None
    # 允许的源节点类型列表（None表示不限制）
    allowed_src_node_types: Optional[Set[NodeType]] = None
    # 允许的目标节点类型列表（None表示不限制）
    allowed_dst_node_types: Optional[Set[NodeType]] = None
    # 允许的事件动作列表（从edge.props["event.action"]提取，None表示不限制）
    allowed_event_actions: Optional[Set[str]] = None
    # 优先级（数字越小优先级越高，用于排序候选锚点）
    priority: int = 0


# 语义规则映射表：键为 (from_state, to_state)，值为规则列表（按优先级排序）
ANCHOR_SEMANTIC_RULES: Dict[Tuple[AttackState, AttackState], List[AnchorSemanticRule]] = {
    # Initial Access -> Execution
    (AttackState.INITIAL_ACCESS, AttackState.EXECUTION): [
        AnchorSemanticRule(
            allowed_reltypes={RelType.SPAWN, RelType.RUNS_ON},
            allowed_dst_node_types={NodeType.PROCESS},
            priority=1,
        ),
    ],
    # Execution -> Privilege Escalation
    (AttackState.EXECUTION, AttackState.PRIVILEGE_ESCALATION): [
        AnchorSemanticRule(
            allowed_reltypes={RelType.SPAWN},
            allowed_dst_node_types={NodeType.PROCESS},
            allowed_event_actions={"process_start"},
            priority=1,
        ),
    ],
    # Privilege Escalation -> Lateral Movement
    (AttackState.PRIVILEGE_ESCALATION, AttackState.LATERAL_MOVEMENT): [
        AnchorSemanticRule(
            allowed_reltypes={RelType.NET_CONNECT},
            allowed_src_node_types={NodeType.PROCESS, NodeType.HOST},
            allowed_dst_node_types={NodeType.IP},
            allowed_event_actions={"network_connection"},
            priority=1,
        ),
    ],
    # Lateral Movement -> Command and Control
    (AttackState.LATERAL_MOVEMENT, AttackState.COMMAND_AND_CONTROL): [
        # 从 C2 段提取 src_uid（Process），匹配 SPAWN/RUNS_ON 的 dst 或 DNS_QUERY 的 src
        AnchorSemanticRule(
            allowed_reltypes={RelType.SPAWN, RelType.RUNS_ON},
            allowed_dst_node_types={NodeType.PROCESS},
            priority=1,
        ),
        AnchorSemanticRule(
            allowed_reltypes={RelType.DNS_QUERY, RelType.NET_CONNECT},
            allowed_src_node_types={NodeType.PROCESS},  # 从 C2 段提取 src（Process）
            priority=2,
        ),
        AnchorSemanticRule(
            allowed_reltypes={RelType.DNS_QUERY, RelType.NET_CONNECT},
            allowed_dst_node_types={NodeType.DOMAIN, NodeType.IP},
            priority=3,
        ),
    ],
    # Command and Control -> Impact
    (AttackState.COMMAND_AND_CONTROL, AttackState.IMPACT): [
        # 从 C2 段提取 dst_uid（Domain/IP），或从 Impact 段提取 src_uid（Process）
        AnchorSemanticRule(
            allowed_reltypes={RelType.FILE_ACCESS, RelType.SPAWN},
            allowed_dst_node_types={NodeType.FILE, NodeType.PROCESS},
            allowed_event_actions={"file_delete", "file_write", "process_start"},
            priority=1,
        ),
        # 允许从 C2 段的 DNS_QUERY 提取 dst（Domain），或从 Impact 段的 FILE_ACCESS 提取 src（Process）
        AnchorSemanticRule(
            allowed_reltypes={RelType.DNS_QUERY},
            allowed_dst_node_types={NodeType.DOMAIN},
            priority=2,
        ),
        AnchorSemanticRule(
            allowed_reltypes={RelType.FILE_ACCESS},
            allowed_src_node_types={NodeType.PROCESS},  # 从 Impact 段提取 src（Process）
            priority=3,
        ),
    ],
}


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
    confidence: float = 0.0  # LLM 评估的可信度评分 (0.0-1.0)
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


def _extract_candidate_anchors_from_segment(
    segment: StateSegment,
    rules: List[AnchorSemanticRule],
    *,
    extract_dst: bool = True,  # True: 提取dst_uid作为候选锚点; False: 提取src_uid
) -> List[str]:
    """
    根据语义规则从段中提取候选锚点。
    
    Args:
        segment: FSA段
        rules: 语义规则列表（已按优先级排序）
        extract_dst: True表示提取边的dst_uid，False表示提取src_uid
    
    Returns:
        候选锚点UID列表（去重，按规则优先级排序）
    """
    # 返回列表（保持顺序：先匹配高优先级规则的锚点）
    result = []
    seen = set()
    for rule in rules:
        for node in segment.nodes:
            if not hasattr(node, "edge"):
                continue
            edge = node.edge
            
            # 使用OR逻辑：只要满足任一条件即可
            matched = False
            
            # 获取节点类型
            src_type = _ntype_of(edge.src_uid)
            dst_type = _ntype_of(edge.dst_uid)
            
            # 根据 extract_dst 决定要检查的节点类型
            target_type = dst_type if extract_dst else src_type
            target_node_types = rule.allowed_dst_node_types if extract_dst else rule.allowed_src_node_types
            
            # 检查关系类型
            if rule.allowed_reltypes is not None:
                if edge.rtype in rule.allowed_reltypes:
                    matched = True
            
            # 检查目标节点类型（根据 extract_dst 选择检查 src 或 dst）
            if not matched and target_node_types is not None:
                if target_type in target_node_types:
                    matched = True
            
            # 如果 extract_dst=False，也检查 allowed_dst_node_types（因为可能规则定义的是 dst）
            if not matched and not extract_dst and rule.allowed_dst_node_types is not None:
                if dst_type in rule.allowed_dst_node_types:
                    matched = True
            
            # 如果 extract_dst=True，也检查 allowed_src_node_types（因为可能规则定义的是 src）
            if not matched and extract_dst and rule.allowed_src_node_types is not None:
                if src_type in rule.allowed_src_node_types:
                    matched = True
            
            # 检查事件动作
            if not matched and rule.allowed_event_actions is not None:
                event_action = edge.props.get("event.action")
                if isinstance(event_action, str) and event_action in rule.allowed_event_actions:
                    matched = True
            
            # 如果所有条件都是None，则默认匹配（允许所有边）
            if not matched and rule.allowed_reltypes is None and rule.allowed_src_node_types is None and rule.allowed_dst_node_types is None and rule.allowed_event_actions is None:
                matched = True
            
            # 如果匹配，提取候选锚点
            if matched:
                candidate_uid = edge.dst_uid if extract_dst else edge.src_uid
                if candidate_uid and candidate_uid not in seen:
                    seen.add(candidate_uid)
                    result.append(candidate_uid)
    
    return result


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
    使用"边池"在本地枚举路径（BFS，限制 hop 数，限制数量 k_limit）。

    说明：
    - 为了鲁棒性，我们将图视为"可无向连通"（即既可沿 edge.src->dst，也可反向走），
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

        neighbors = adj.get(cur_uid, [])
        for nxt_uid, edge in neighbors:
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


def _enumerate_paths_reverse_to_segment(
    edge_pool: Sequence[GraphEdge],
    *,
    src_anchor: str,  # 从下一个段的 anchor_in_uid 开始反向搜索
    segment_node_uids: Set[str],  # 当前段的所有节点 UID（src_uid 和 dst_uid）
    t_min: float,
    t_max: float,
    allowed_reltypes: Sequence[Any],
    max_hops: int,
    k_limit: int,
) -> List[List[GraphEdge]]:
    """
    反向搜索：从 dst_anchor 开始，尝试连接到段内任意节点。
    返回的路径需要反转（因为是从 dst 到 src_segment 的任意节点）。
    """
    allowed = _normalize_reltypes(allowed_reltypes)
    
    # 构建无向邻接表
    adj: Dict[str, List[Tuple[str, GraphEdge]]] = {}
    for e in edge_pool:
        if e.rtype.value not in allowed:
            continue
        ts = _edge_ts(e)
        if ts < t_min or ts > t_max:
            continue
        adj.setdefault(e.src_uid, []).append((e.dst_uid, e))
        adj.setdefault(e.dst_uid, []).append((e.src_uid, e))
    
    if src_anchor not in adj:
        return []
    
    # BFS：从 src_anchor（下一个段的 anchor_in_uid）开始，搜索到段内任意节点
    queue: Deque[Tuple[str, List[GraphEdge], Set[str], float]] = deque()
    queue.append((src_anchor, [], {src_anchor}, t_max))  # 反向搜索，从 t_max 开始
    
    found: List[List[GraphEdge]] = []
    
    while queue and len(found) < k_limit:
        cur_uid, path_edges, visited, last_ts = queue.popleft()
        
        # 如果到达段内任意节点，记录路径（需要反转）
        if cur_uid in segment_node_uids:
            if path_edges:
                # 反转路径（因为是从 dst 到 src），然后检查时间单调性
                reversed_path = list(reversed(path_edges))
                if _is_time_monotonic(reversed_path, tolerance=TIME_SKEW_TOLERANCE_SEC):
                    found.append(reversed_path)
            continue
        
        if len(path_edges) >= max_hops:
            continue
        
        for nxt_uid, edge in adj.get(cur_uid, []):
            if nxt_uid in visited:
                continue
            
            ts = _edge_ts(edge)
            # 反向搜索：放宽时间限制
            # 只拒绝明显超出时间窗口的边
            if ts < t_min or ts > t_max:
                continue
            # 对于反向搜索，我们完全放宽时间单调性检查
            # 因为路径反转后，时间顺序会重新排序，所以不需要严格的时间递减检查
            # 只要边在时间窗口内，就接受它
            
            new_edges = path_edges + [edge]
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
    src_segment_nodes: Optional[Set[str]] = None,  # 新增：当前段的所有节点 UID，用于反向搜索
) -> List[CandidatePath]:
    """
    多级枚举 + 缓存：
    Stage1: (max_hops, FIRST_K)
    Stage2: (max_hops+2, SECOND_K) 仅在 Stage1 无结果时触发
    Stage3: 反向搜索（如果 src_segment_nodes 提供且正向搜索失败）
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
    
    if cand2:
        return cand2
    
    # ---------- Stage 3: 反向搜索（如果正向搜索失败且提供了 src_segment_nodes） ----------
    if src_segment_nodes is not None and len(src_segment_nodes) > 0:
        # 获取边池（重用 Stage 2 的边池）
        edge_pool_reverse = edge_pool2 if 'edge_pool2' in locals() else (
            res2 if isinstance(res2, list) and res2 and isinstance(res2[0], GraphEdge) else []
        )
        
        # 如果没有边池，重新获取
        if not edge_pool_reverse:
            res_reverse = _get_edges_inter_nodes(
                t_min=t_min,
                t_max=t_max,
                allowed_reltypes=allowed_reltypes
            )
            edge_pool_reverse = _coerce_api_result_to_edge_pool(res_reverse) or []
        
        # 反向搜索：从 dst_anchor 到 src_segment 的任意节点
        reverse_paths = _enumerate_paths_reverse_to_segment(
            edge_pool_reverse,
            src_anchor=dst_anchor,  # 从下一个段的 anchor_in_uid 开始
            segment_node_uids=src_segment_nodes,  # 搜索到当前段的任意节点
            t_min=t_min,
            t_max=t_max,
            allowed_reltypes=allowed_reltypes,
            max_hops=max_hops2,
            k_limit=SECOND_K,
        )
        
        if reverse_paths:
            # 将反向路径转换为 CandidatePath（路径已经反转，src_anchor 和 dst_anchor 保持不变）
            cand3 = [_build_candidate_from_edges(src_anchor, dst_anchor, t_min, t_max, p) for p in reverse_paths]
            cand3 = _dedup_paths(cand3, limit=MAX_PATHS_PER_PAIR)
            return cand3
    
    return cand2


def connect_fsa_segments_to_candidates(
    fsa_graph: FSAGraph,
    *,
    cache: AnchorPairCache,
    allowed_reltypes: Sequence[Any] = ALLOWED_RELTYPES,
) -> Tuple[Optional[SemanticCandidateSubgraph], Optional[DroppedFSAGraph]]:
    """
    Phase B：连接所有相邻段锚点，生成候选通路集合。
    - 任意相邻锚点无候选 => return (None, DroppedFSAGraph)（丢弃该图）
    
    返回:
        (SemanticCandidateSubgraph, None) 如果成功
        (None, DroppedFSAGraph) 如果失败
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
        ), None

    pair_candidates: List[AnchorPairCandidates] = []
    trace: List[Dict[str, Any]] = []
    last_connected_state: Optional[str] = None

    for i in range(len(segments) - 1):
        seg = segments[i]
        nxt = segments[i + 1]

        # 1. 首先尝试默认锚点
        src_anchor = seg.anchor_out_uid
        dst_anchor = nxt.anchor_in_uid

        # 锚点不能为空
        if not src_anchor or not dst_anchor:
            trace.append({"phase": "B", "pair_idx": i, "reason": "empty_anchor", "src": src_anchor, "dst": dst_anchor})
            dropped = DroppedFSAGraph(
                fsa_graph=fsa_graph,
                last_connected_state=last_connected_state,
                failed_transition=(seg.state, nxt.state) if seg.state and nxt.state else None,
            )
            return None, dropped

        t_min, t_max = _anchor_window(seg.t_end, nxt.t_start, margin_sec=TIME_MARGIN_SEC)
        if t_min > t_max:
            trace.append({"phase": "B", "pair_idx": i, "reason": "invalid_time_window", "t_min": t_min, "t_max": t_max})
            dropped = DroppedFSAGraph(
                fsa_graph=fsa_graph,
                last_connected_state=last_connected_state,
                failed_transition=(seg.state, nxt.state) if seg.state and nxt.state else None,
            )
            return None, dropped

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

        # 2. 获取语义规则
        try:
            from_state = AttackState(seg.state)
            to_state = AttackState(nxt.state)
            semantic_rules = ANCHOR_SEMANTIC_RULES.get((from_state, to_state), [])
        except (ValueError, KeyError):
            semantic_rules = []

        # 初始化变量
        src_segment_node_uids: Set[str] = set()
        cands = None

        # 3. 首先尝试默认锚点连接
        if src_anchor and dst_anchor:
            # 收集当前段的所有节点 UID（用于反向搜索）
            # 从 fsa_graph 中获取对应段的节点
            fsa_segments = fsa_graph.segments()
            if i < len(fsa_segments):
                seg_nodes = fsa_segments[i].nodes
                for node in seg_nodes:
                    if hasattr(node, 'src_uid') and node.src_uid:
                        src_segment_node_uids.add(node.src_uid)
                    if hasattr(node, 'dst_uid') and node.dst_uid:
                        src_segment_node_uids.add(node.dst_uid)
            # 也添加 anchor_out_uid 和 anchor_in_uid（段的第一个和最后一个节点）
            if src_anchor:
                src_segment_node_uids.add(src_anchor)
            if seg.anchor_in_uid:
                src_segment_node_uids.add(seg.anchor_in_uid)
            
            cands = enumerate_candidate_paths_multi_stage(
                cache=cache,
                src_anchor=src_anchor,
                dst_anchor=dst_anchor,
                t_min=t_min,
                t_max=t_max,
                allowed_reltypes=allowed_reltypes,
                max_hops=max_hops,
                src_segment_nodes=src_segment_node_uids if src_segment_node_uids else None,
            )

        # 4. 如果默认锚点失败且存在语义规则，尝试语义锚点
        if not cands:
            print(f"[WARN] 默认锚点连接失败，尝试使用语义锚点: {seg.state} -> {nxt.state}")
            if semantic_rules:
                fsa_segments = fsa_graph.segments()
                src_segment = fsa_segments[i] if i < len(fsa_segments) else None
                dst_segment = fsa_segments[i + 1] if i + 1 < len(fsa_segments) else None
                
                if src_segment and dst_segment:
                    # 提取候选锚点
                    src_candidates = _extract_candidate_anchors_from_segment(
                        src_segment, semantic_rules, extract_dst=True
                    )
                    dst_candidates = _extract_candidate_anchors_from_segment(
                        dst_segment, semantic_rules, extract_dst=False
                    )
                    
                    # 如果候选列表为空，添加默认锚点作为fallback
                    if not src_candidates and src_anchor:
                        src_candidates = [src_anchor]
                    if not dst_candidates and dst_anchor:
                        dst_candidates = [dst_anchor]
                    
                    if not src_candidates or not dst_candidates:
                        print(f"[WARN] 语义规则存在但未找到候选锚点，请检查语义规则配置: {seg.state} -> {nxt.state}")
                        print(f"[WARN]   - 源段候选锚点数: {len(src_candidates)}")
                        print(f"[WARN]   - 目标段候选锚点数: {len(dst_candidates)}")
                        dropped = DroppedFSAGraph(
                            fsa_graph=fsa_graph,
                            last_connected_state=last_connected_state,
                            failed_transition=(seg.state, nxt.state) if seg.state and nxt.state else None,
                        )
                        return None, dropped
                    
                    # 遍历所有候选锚点对
                    for src_cand in src_candidates:
                        for dst_cand in dst_candidates:
                            cands = enumerate_candidate_paths_multi_stage(
                                cache=cache,
                                src_anchor=src_cand,
                                dst_anchor=dst_cand,
                                t_min=t_min,
                                t_max=t_max,
                                allowed_reltypes=allowed_reltypes,
                                max_hops=max_hops,
                                src_segment_nodes=None,  # 语义锚点模式下不使用反向搜索
                            )
                            if cands:
                                # 找到通路，更新锚点并跳出循环
                                src_anchor = src_cand
                                dst_anchor = dst_cand
                                break
                        if cands:
                            break
                else:
                    print(f"[WARN] 无法获取段信息，请检查 FSA 图结构: {seg.state} -> {nxt.state}")
                    dropped = DroppedFSAGraph(
                        fsa_graph=fsa_graph,
                        last_connected_state=last_connected_state,
                        failed_transition=(seg.state, nxt.state) if seg.state and nxt.state else None,
                    )
                    return None, dropped
            else:
                print(f"[WARN] 未找到语义规则，请添加语义规则配置: {seg.state} -> {nxt.state}")
                dropped = DroppedFSAGraph(
                    fsa_graph=fsa_graph,
                    last_connected_state=last_connected_state,
                    failed_transition=(seg.state, nxt.state) if seg.state and nxt.state else None,
                )
                return None, dropped

        # 5. 如果仍然没有找到通路，返回None（丢弃该图）
        if not cands:
            trace.append({"phase": "B", "pair_idx": i, "reason": "no_path_candidates", 
                         "tried_semantic": bool(semantic_rules), "tried_reverse": bool(src_segment_node_uids)})
            dropped = DroppedFSAGraph(
                fsa_graph=fsa_graph,
                last_connected_state=last_connected_state,
                failed_transition=(seg.state, nxt.state) if seg.state and nxt.state else None,
            )
            return None, dropped

        # 成功连接，更新最后连接状态
        last_connected_state = nxt.state

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
    ), None


def build_semantic_candidate_subgraphs(
    graphs: Sequence[FSAGraph],
    *,
    cache: Optional[AnchorPairCache] = None,
    allowed_reltypes: Sequence[Any] = ALLOWED_RELTYPES,
) -> Tuple[List[SemanticCandidateSubgraph], List[DroppedFSAGraph]]:
    """
    对所有 FSAGraph 运行 Phase B，输出"可联通"的候选子图列表。
    
    返回:
        (候选子图列表, 被丢弃的图列表)
    """
    cache = cache or AnchorPairCache()
    out: List[SemanticCandidateSubgraph] = []
    dropped: List[DroppedFSAGraph] = []
    
    for g in graphs:
        cand, dropped_info = connect_fsa_segments_to_candidates(g, cache=cache, allowed_reltypes=allowed_reltypes)
        if cand is None:
            if dropped_info is not None:
                dropped.append(dropped_info)
            continue
        out.append(cand)
    
    return out, dropped


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
    kc_uuid: str | None = None,
    *,
    llm_client: KillChainLLMClient = None,
) -> KillChain:
    """
    Phase C：LLM 选择全链最可能路径。

    你们接入真实 LLM 时建议约定 llm_client 接口：
      llm_client.choose(payload: dict) -> dict:
        {
          "chosen_path_ids": ["p-...", "p-...", ...],   # 顺序与 pairs 一致
          "explanation": "...",
          "confidence": 0.85  # 可信度评分 (0.0-1.0)，可选
        }

    当前 stub 策略（可跑通）：
      - 每个 pair 选择 hop 最短的一条（edges 数最少）
      - explanation 写入简单占位文本
      - confidence 默认为 0.5（fallback 模式）
    """
    if kc_uuid is None:
        kc_uuid = str(uuid.uuid4())

    payload = build_llm_payload(candidate)

    chosen_ids: List[str] = []
    explanation: str = ""
    confidence: float = 0.5  # 默认可信度（fallback 模式）
    
    # 如果 pairs 为空，直接使用 fallback，不调用 LLM
    if not payload.get('pairs'):
        explanation = (
            "检测到的攻击链仅包含单个攻击阶段，无需连接多个段。"
            "该攻击链直接使用 FSA（有限状态自动机）识别的异常边构建，"
            "未涉及跨阶段的路径选择。"
            "由于攻击链结构简单，未调用大语言模型进行路径选择分析。"
            "建议检查数据源，确认是否包含完整的攻击链信息。"
        )
        confidence = 0.3  # 单段 killchain 可信度较低
    elif llm_client is not None and hasattr(llm_client, "choose"):
        try:
            res = llm_client.choose(payload)
            if isinstance(res, Mapping):
                ids = res.get("chosen_path_ids")
                if isinstance(ids, list) and all(isinstance(x, str) for x in ids):
                    chosen_ids = list(ids)
                exp = res.get("explanation")
                if isinstance(exp, str):
                    explanation = exp
                # 提取可信度评分
                conf = res.get("confidence")
                if isinstance(conf, (int, float)):
                    confidence = float(conf)
                    # 确保在 0.0-1.0 范围内
                    confidence = max(0.0, min(1.0, confidence))
        except Exception:
            pass  # 继续执行 fallback 逻辑

    # fallback：最短 hop
    if not chosen_ids:
        for p in candidate.pair_candidates:
            if not p.candidates:
                continue
            best = min(p.candidates, key=lambda c: len(c.edges))
            chosen_ids.append(best.path_id)
        explanation = (
            "由于大语言模型不可用或调用失败，系统使用回退策略为每个锚点对选择了跳数最短的路径。"
            "回退策略基于最短路径启发式算法，优先选择连接段对之间跳数最少的路径，"
            "以确保攻击链的基本连通性和时间一致性。"
            "虽然这种方法能够构建完整的攻击链，但由于缺乏智能语义分析，"
            "可能无法识别最优的攻击路径。"
            "建议配置大语言模型 API 密钥后重新运行分析，以获得更准确和详细的攻击链解释。"
        )
        confidence = 0.5  # fallback 模式的可信度

    killchain = materialize_killchain(candidate, chosen_ids, kc_uuid, explanation=explanation, confidence=confidence)
    return killchain


def materialize_killchain(
    candidate: SemanticCandidateSubgraph,
    chosen_path_ids: Sequence[str],
    kc_uuid: str | None = None,
    *,
    explanation: str,
    confidence: float = 0.5,
) -> KillChain:
    """把 LLM 输出的 path_id 列表映射回 CandidatePath，生成最终 KillChain。"""
    if kc_uuid is None:
        kc_uuid = str(uuid.uuid4())

    # 建立 path_id -> CandidatePath 的索引
    idx: Dict[str, CandidatePath] = {}
    for p in candidate.pair_candidates:
        for c in p.candidates:
            idx[c.path_id] = c

    selected: List[CandidatePath] = []
    for pid in chosen_path_ids:
        if not pid:  # 跳过空字符串
            continue
        c = idx.get(pid)
        if c is None:
            # 若 LLM 返回了不存在的 id，直接忽略（也可 raise，按你们偏好）
            continue
        selected.append(c)

    return KillChain(
        kc_uuid=kc_uuid,
        fsa_graph=candidate.fsa_graph,
        segments=candidate.segments,
        selected_paths=selected,
        explanation=explanation,
        confidence=confidence,
        trace=list(candidate.trace),
    )


# ---------------------------------------------------------------------------
# Persist: annotate edges/nodes with kc_uuid (ECS: custom.killchain.uuid)
# ---------------------------------------------------------------------------
def persist_killchain_to_db(kc: KillChain) -> None:
    """
    将 killchain 结果落库（仅靠在 props 写 kc_uuid）：

    逻辑：
      1) 收集 killchain 涉及的边（FSA key edges + Phase C 选中的连接边）
      2) 对每条边写入 analysis.task_id
      3) 对边涉及的节点 uid 生成最小 GraphNode，并写入 analysis.task_id
      4) 调用 graph_api.set_analysis_task_id 写入数据库

    注意：
      - 使用 analysis.task_id 字段存储 killchain uuid
    """
    if not hasattr(graph_api, "set_analysis_task_id"):
        raise RuntimeError("graph_api.set_analysis_task_id not found; cannot persist killchain.")

    set_analysis_task_id = graph_api.set_analysis_task_id
    get_node = graph_api.get_node

    kc_uuid = kc.kc_uuid

    # 1) 收集边（去重：按 stable edge id）
    edges: List[GraphEdge] = []
    seen_e: Set[str] = set()

    # 1.1 FSA key edges
    fsa_nodes = getattr(kc.fsa_graph, "nodes", [])
    for n in fsa_nodes:
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
        if not isinstance(getattr(e, "props", None), dict):
            e.props = {}
        e.props[KC_ECS_FIELD] = kc_uuid
        graph_api.add_edge(e)

    # 3) 收集节点 uid（从边端点）
    node_uids: Set[str] = set()
    for e in edges:
        node_uids.add(e.src_uid)
        node_uids.add(e.dst_uid)

    # 4) 生成最小节点并 merge 写入
    for uid in node_uids:
        node = get_node(uid)
        if node is None:
            continue
        set_analysis_task_id(node, kc_uuid)




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
    kc_uuid: str | None = None,
    llm_client: Any = None,
    persist: bool = True,
) -> List[KillChain]:
    """
    完整流水线：
      abnormal -> PhaseA(FSA) -> PhaseB(candidate) -> PhaseC(LLM choose) -> persist kc_uuid -> return killchains
    
    注意：
      - 如果 persist=True，只会将可信度最高的 killchain 存入数据库
      - 所有 killchains 都会返回，但只有最高可信度的会被持久化
    """
    if kc_uuid is None:
        kc_uuid = str(uuid.uuid4())

    abnormal = graph_api.get_alarm_edges()

    # Phase A
    fsa_graphs = behavior_state_machine(abnormal)

    # Phase B
    cache = AnchorPairCache(max_items=MAX_CACHE_ITEMS)
    candidates, dropped = build_semantic_candidate_subgraphs(fsa_graphs, cache=cache)
    
    if not candidates:
        _log_dropped_killchains(dropped)
        return []
    
    print(f"[INFO] candidates count: {len(candidates)}")

    # Phase C: 生成所有 killchains
    killchains: List[KillChain] = []
    for i,cand in enumerate(candidates):
        print(f"[INFO] select_killchain_with_llm: {i+1}/{len(candidates)}")
        kc = select_killchain_with_llm(cand, kc_uuid, llm_client=llm_client)
        killchains.append(kc)

    # 如果最终没有任何 killchain 被保留，输出被丢弃的图信息
    if not killchains and dropped:
        _log_dropped_killchains(dropped)

    # 只持久化可信度最高的 killchain
    if persist and killchains:
        # 找到可信度最高的 killchain
        best_kc = max(killchains, key=lambda kc: kc.confidence)
        persist_killchain_to_db(best_kc)

    return killchains
