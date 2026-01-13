# attack_fsa.py
from __future__ import annotations

"""
Phase A: Attack FSA (Finite-State Automaton) builder.

目标：
- 输入 abnormal_edges（告警/异常边，GraphEdge）
- 将每条边按 attack_tag 映射到 ATT&CK tactic（14个官方战术）
- 按 transition policy 检查状态转移是否被接受
- 当遇到不接受的转移时，同时尝试两种分支策略：
  1) POP：回溯（pop）若干关键边，直到该边可接入
  2) DROP：丢弃该边（认为可能是噪声/干扰项）
  两个分支只要最终都能到达 accept_states，就都输出（多图输出）
- 最终对外仅暴露：behavior_state_machine() -> List[FSAGraph]

工程化注意点：
- Beam search + 去重：避免分支爆炸
- FSAGraph.nodes 中只包含关键边（is_key=True, is_completion=False）
  Phase B 会插入 completion 边（is_completion=True）
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ..graph.models import GraphEdge
from ..graph.utils import _parse_ts_to_float


class AttackState(str, Enum):
    """MITRE ATT&CK tactic names (official 14 tactics)."""

    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


# ---- Tag -> state mapping (supports internal compact strings & MITRE display strings) ----
# 说明：
# - 你们 edge.get_attack_tag() 可能返回内部紧凑格式（无空格）或 MITRE 展示格式（带空格）
# - 这里统一映射到 AttackState 枚举
TAG_TO_STATE: Dict[str, AttackState] = {
    # Project-friendly tags (no spaces)
    "Reconnaissance": AttackState.RECONNAISSANCE,
    "ResourceDevelopment": AttackState.RESOURCE_DEVELOPMENT,
    "InitialAccess": AttackState.INITIAL_ACCESS,
    "Execution": AttackState.EXECUTION,
    "Persistence": AttackState.PERSISTENCE,
    "PrivilegeEscalation": AttackState.PRIVILEGE_ESCALATION,
    "DefenseEvasion": AttackState.DEFENSE_EVASION,
    "CredentialAccess": AttackState.CREDENTIAL_ACCESS,
    "Discovery": AttackState.DISCOVERY,
    "LateralMovement": AttackState.LATERAL_MOVEMENT,
    "Collection": AttackState.COLLECTION,
    "CommandAndControl": AttackState.COMMAND_AND_CONTROL,
    "Exfiltration": AttackState.EXFILTRATION,
    "Impact": AttackState.IMPACT,
    # MITRE display names (with spaces)
    "Resource Development": AttackState.RESOURCE_DEVELOPMENT,
    "Initial Access": AttackState.INITIAL_ACCESS,
    "Privilege Escalation": AttackState.PRIVILEGE_ESCALATION,
    "Defense Evasion": AttackState.DEFENSE_EVASION,
    "Credential Access": AttackState.CREDENTIAL_ACCESS,
    "Lateral Movement": AttackState.LATERAL_MOVEMENT,
    "Command and Control": AttackState.COMMAND_AND_CONTROL,
}


@dataclass(frozen=True, slots=True)
class TransitionPolicy:
    """
    Finite-state transition policy.

    allowed_next:
        指定每个状态允许的后继状态集合
    allow_self_loop:
        是否允许同状态连续出现（同一阶段多条告警）
    allow_start_anywhere:
        若 from_state is None（链条尚未开始），是否允许以任意状态开始
    max_state_skip / allow_jump_pairs:
        可选的“跳转控制”，当前实现里只显式支持 allow_jump_pairs
    """

    allowed_next: Dict[AttackState, Set[AttackState]]
    allow_self_loop: bool = True
    allow_start_anywhere: bool = True

    # Optional knobs（保留位：未来可用于更严格/更松的跳转规则）
    max_state_skip: Optional[int] = None
    allow_jump_pairs: Set[Tuple[AttackState, AttackState]] = field(default_factory=set)


def default_transition_policy() -> TransitionPolicy:
    """
    A reasonable default transition policy for 14 ATT&CK tactics.

    注意：
    - 这不是 MITRE 官方“严格序”，而是面向实战数据的“宽松可接受序”
    - 允许多种常见循环/跳转（例如 discovery -> privilege escalation）
    """
    A = AttackState
    allowed: Dict[AttackState, Set[AttackState]] = {
        A.RECONNAISSANCE: {A.RESOURCE_DEVELOPMENT, A.INITIAL_ACCESS, A.EXECUTION},
        A.RESOURCE_DEVELOPMENT: {A.INITIAL_ACCESS, A.EXECUTION},
        A.INITIAL_ACCESS: {A.EXECUTION, A.PERSISTENCE, A.PRIVILEGE_ESCALATION, A.DEFENSE_EVASION},
        A.EXECUTION: {
            A.PERSISTENCE,
            A.PRIVILEGE_ESCALATION,
            A.DEFENSE_EVASION,
            A.CREDENTIAL_ACCESS,
            A.DISCOVERY,
            A.LATERAL_MOVEMENT,
            A.COLLECTION,
            A.COMMAND_AND_CONTROL,
            A.EXFILTRATION,
            A.IMPACT,
        },
        A.PERSISTENCE: {
            A.PRIVILEGE_ESCALATION,
            A.DEFENSE_EVASION,
            A.CREDENTIAL_ACCESS,
            A.DISCOVERY,
            A.LATERAL_MOVEMENT,
            A.COLLECTION,
            A.COMMAND_AND_CONTROL,
        },
        A.PRIVILEGE_ESCALATION: {
            A.DEFENSE_EVASION,
            A.CREDENTIAL_ACCESS,
            A.DISCOVERY,
            A.LATERAL_MOVEMENT,
            A.COLLECTION,
            A.COMMAND_AND_CONTROL,
            A.EXFILTRATION,
            A.IMPACT,
        },
        A.DEFENSE_EVASION: {
            A.CREDENTIAL_ACCESS,
            A.DISCOVERY,
            A.LATERAL_MOVEMENT,
            A.COLLECTION,
            A.COMMAND_AND_CONTROL,
        },
        A.CREDENTIAL_ACCESS: {
            A.DISCOVERY,
            A.LATERAL_MOVEMENT,
            A.COLLECTION,
            A.COMMAND_AND_CONTROL,
        },
        A.DISCOVERY: {
            A.LATERAL_MOVEMENT,
            A.COLLECTION,
            A.COMMAND_AND_CONTROL,
            A.EXFILTRATION,
            A.IMPACT,
            A.PRIVILEGE_ESCALATION,  # common loop
        },
        A.LATERAL_MOVEMENT: {
            A.EXECUTION,
            A.PRIVILEGE_ESCALATION,
            A.DEFENSE_EVASION,
            A.DISCOVERY,
            A.COLLECTION,
            A.COMMAND_AND_CONTROL,
            A.EXFILTRATION,
            A.IMPACT,
        },
        A.COLLECTION: {A.COMMAND_AND_CONTROL, A.EXFILTRATION, A.IMPACT},
        A.COMMAND_AND_CONTROL: {A.EXFILTRATION, A.IMPACT},
        A.EXFILTRATION: {A.IMPACT},
        A.IMPACT: set(),
    }
    return TransitionPolicy(allowed_next=allowed, allow_self_loop=True, allow_start_anywhere=True)


class EdgeNode:
    """
    Edge wrapper.
    要求：不要改字段，只通过 property 暴露。

    设计意图：
    - 让上层统一通过 Node 抽象访问 edge 的常用属性（uid、ts、attack_tag、state）
    - 不把 state/ts 直接写回 edge.props，保持“只读视图”的意味
    """

    __slots__ = ("_edge",)

    def __init__(self, edge: GraphEdge):
        self._edge = edge

    @property
    def edge(self) -> GraphEdge:
        return self._edge

    @property
    def src_uid(self) -> str:
        return self._edge.src_uid

    @property
    def dst_uid(self) -> str:
        return self._edge.dst_uid

    @property
    def rtype(self):
        return self._edge.rtype

    @property
    def props(self):
        return self._edge.props

    @property
    def ts(self) -> float:
        """
        统一时间戳入口：
        - GraphEdge 可能实现 get_ts()
        - _parse_ts_to_float(None) 应该返回 0.0 或可处理空值（由 utils 决定）
        """
        raw = self._edge.get_ts() if hasattr(self._edge, "get_ts") else None
        return _parse_ts_to_float(raw)

    @property
    def attack_tag(self) -> Optional[str]:
        """从边上读取 attack tag（若实现 get_attack_tag）。"""
        return self._edge.get_attack_tag() if hasattr(self._edge, "get_attack_tag") else None

    @property
    def state(self) -> Optional[AttackState]:
        """由 attack_tag 映射到 AttackState；不在表里则返回 None。"""
        tag = self.attack_tag
        if not tag:
            return None
        return TAG_TO_STATE.get(tag)


class KillChainEdgeNode(EdgeNode):
    """
    子类可加字段：
    - is_key: 是否被 Phase A 选为关键边（状态机骨架）
    - is_completion: 是否是 Phase B 补全得到的边（路径连接边）
    """

    __slots__ = ("_is_key", "_is_completion")

    def __init__(self, edge: GraphEdge, *, is_key: bool, is_completion: bool):
        super().__init__(edge)
        self._is_key = bool(is_key)
        self._is_completion = bool(is_completion)

    @property
    def is_key(self) -> bool:
        return self._is_key

    @property
    def is_completion(self) -> bool:
        return self._is_completion


@dataclass(slots=True)
class StateSegment:
    """
    StateSegment 用于 Phase B（图补全）：
    - 将 Phase A 的关键边按 state 聚合成连续段
    - 每段提供时间窗口与锚点（anchor）用于段间连接
    """

    state: AttackState
    nodes: List[EdgeNode]

    @property
    def t_start(self) -> float:
        return self.nodes[0].ts if self.nodes else 0.0

    @property
    def t_end(self) -> float:
        return self.nodes[-1].ts if self.nodes else 0.0

    @property
    def anchor_in_uid(self) -> str:
        # 作为下一段连接的“进入锚点”
        return self.nodes[0].src_uid if self.nodes else ""

    @property
    def anchor_out_uid(self) -> str:
        # 作为本段对外的“退出锚点”
        return self.nodes[-1].dst_uid if self.nodes else ""


@dataclass(slots=True)
class FSAGraph:
    """
    Phase A 的输出图（骨架）：
    - nodes: EdgeNode 列表（包含 key 边；Phase B 可能插入 completion 边）
    - trace: 记录分支/补全日志，便于 debug / 解释
    """

    nodes: List[EdgeNode]
    trace: List[Dict[str, Any]] = field(default_factory=list)

    def segments(self) -> List[StateSegment]:
        """
        将 nodes 划分为按 state 连续的段。

        重要约定：
        - Phase B 插入的 completion 边（is_completion=True）不参与分段
          因为分段只关心 Phase A 的关键“状态骨架”。
        """
        key_nodes: List[EdgeNode] = []
        for n in self.nodes:
            if getattr(n, "is_completion", False):
                continue
            key_nodes.append(n)

        segments: List[StateSegment] = []
        for n in key_nodes:
            s = n.state
            if s is None:
                continue
            if not segments or segments[-1].state != s:
                segments.append(StateSegment(state=s, nodes=[n]))
            else:
                segments[-1].nodes.append(n)
        return segments

    @property
    def t_start(self) -> float:
        return self.nodes[0].ts if self.nodes else 0.0

    @property
    def t_end(self) -> float:
        return self.nodes[-1].ts if self.nodes else 0.0


# -----------------------------
# Internal-only structures below
# -----------------------------

@dataclass(slots=True)
class _SegmentBuilder:
    """
    Phase A 内部使用的“可变段”，用于 POP 回溯时能 pop 掉末尾边。
    与 StateSegment 的区别：
    - StateSegment 是最终读视图（EdgeNode）
    - _SegmentBuilder 是构建过程中的可变结构（KillChainEdgeNode）
    """

    state: AttackState
    nodes: List[KillChainEdgeNode] = field(default_factory=list)

    def pop_one(self) -> Optional[KillChainEdgeNode]:
        if not self.nodes:
            return None
        return self.nodes.pop()

    @property
    def last_node(self) -> Optional[KillChainEdgeNode]:
        return self.nodes[-1] if self.nodes else None


@dataclass(slots=True)
class _Hypothesis:
    """
    “路径假设”：
    - segments: 状态段列表（可变构建器）
    - drops/pops: 分支策略统计（用于 score_hint）
    - trace: 记录在第几个 key node 处做了什么决策（POP/DROP）
    """

    segments: List[_SegmentBuilder] = field(default_factory=list)
    drops: int = 0
    pops: int = 0
    trace: List[Dict[str, Any]] = field(default_factory=list)

    def clone(self) -> "_Hypothesis":
        """
        深拷贝一份 hypothesis，用于分支扩展。
        注意：segments.nodes 是 list，需要复制，否则分支间会互相污染。
        """
        segs: List[_SegmentBuilder] = []
        for seg in self.segments:
            segs.append(_SegmentBuilder(state=seg.state, nodes=list(seg.nodes)))
        return _Hypothesis(segments=segs, drops=self.drops, pops=self.pops, trace=list(self.trace))

    @property
    def last_state(self) -> Optional[AttackState]:
        return self.segments[-1].state if self.segments else None

    @property
    def last_anchor_out_uid(self) -> Optional[str]:
        """
        用于 dedup key：
        - i（当前位置）
        - last_state（当前末状态）
        - last_anchor_out_uid（末锚点 uid）
        """
        if not self.segments:
            return None
        ln = self.segments[-1].last_node
        return ln.dst_uid if ln else None

    @property
    def key_edge_count(self) -> int:
        """关键边数量（Phase A 节点数），越多通常表示链条更“完整”。"""
        return sum(len(seg.nodes) for seg in self.segments)

    @property
    def score_hint(self) -> float:
        """
        用于 beam 排序/剪枝的启发式分：
        - 越多 key edge 越好
        - DROP/P0P 视为“折损”，会扣分
        """
        return float(self.key_edge_count) - 0.25 * float(self.drops) - 0.5 * float(self.pops)

    def flatten_nodes(self) -> List[KillChainEdgeNode]:
        """把 segments 展平为线性节点序列（输出 FSAGraph 时使用）。"""
        out: List[KillChainEdgeNode] = []
        for seg in self.segments:
            out.extend(seg.nodes)
        return out

    def clear(self) -> None:
        """当到达 accept state 后，按当前策略重置，开始寻找下一条链。"""
        self.segments.clear()
        self.drops = 0
        self.pops = 0
        self.trace.clear()


def _can_transition(policy: TransitionPolicy, from_state: Optional[AttackState], to_state: AttackState) -> bool:
    """
    判断状态转移是否可接受：
    - 未开始（from=None）：由 allow_start_anywhere 控制
    - 自环：由 allow_self_loop 控制
    - 显式 jump pair：allow_jump_pairs
    - 常规：allowed_next[from] 包含 to
    """
    if from_state is None:
        return policy.allow_start_anywhere
    if policy.allow_self_loop and to_state == from_state:
        return True
    if (from_state, to_state) in policy.allow_jump_pairs:
        return True
    return to_state in policy.allowed_next.get(from_state, set())


def behavior_state_machine(
    abnormal_edges: List[GraphEdge],
    *,
    policy: Optional[TransitionPolicy] = None,
    accept_states: Optional[Set[AttackState]] = None,
    max_backtrack_edges: int = 10,
    beam_width: int = 100,
) -> List[FSAGraph]:
    """
    Phase A 对外接口：构造可接受的状态转移图列表。

    参数：
    - abnormal_edges: 异常/告警边列表（通常来自 is_alarm=true）
    - policy: 状态机转移规则（默认 default_transition_policy）
    - accept_states: 接受态集合（默认 {Exfiltration}）
    - max_backtrack_edges: POP 分支最多回溯 pop 的边数
    - beam_width: 同时保留的 hypothesis 数上限（防爆）

    返回：
    - List[FSAGraph]：所有接受的图（多条），每条包含 key nodes 及 trace
    """
    if policy is None:
        policy = default_transition_policy()
    if accept_states is None:
        accept_states = {AttackState.EXFILTRATION, AttackState.IMPACT, AttackState.COMMAND_AND_CONTROL}

    # 1) 先按时间排序，保证处理是顺序的（更接近“真实事件链”）
    edges_sorted = sorted(
        abnormal_edges,
        key=lambda e: _parse_ts_to_float(e.get_ts() if hasattr(e, "get_ts") else None),
    )

    # 2) 将可映射到状态的边包装为 KillChainEdgeNode（Phase A key edge）
    nodes: List[KillChainEdgeNode] = []
    for e in edges_sorted:
        n = KillChainEdgeNode(e, is_key=True, is_completion=False)
        if n.state is None:
            # 没 attack_tag 或不在映射表内：直接跳过，不影响链条
            continue
        nodes.append(n)

    accepted: List[FSAGraph] = []
    active: List[_Hypothesis] = [_Hypothesis()]  # 初始只有一个空假设

    # 3) 逐条 key node 执行状态机，并行维护多 hypothesis
    for i, node in enumerate(nodes):
        next_state = node.state
        if next_state is None:
            continue

        candidates: List[_Hypothesis] = []

        for hypo in active:
            prev_state = hypo.last_state

            # 3.1) 可直接转移：DIRECT 分支
            if _can_transition(policy, prev_state, next_state):
                h = hypo.clone()
                _extend_hypothesis(h, node)
                _maybe_emit_and_reset(h, accept_states, accepted)
                candidates.append(h)
                continue

            # 3.2) 不可转移：分成两条分支
            # Branch 1: POP（回溯 pop 若干边，尝试接入）
            h_pop = hypo.clone()
            ok = _try_pop_until_accept(h_pop, policy, next_state, max_backtrack_edges)
            if ok:
                h_pop.pops += 1
                h_pop.trace.append({"i": i, "decision": "POP", "to_state": next_state.value})
                _extend_hypothesis(h_pop, node)
                _maybe_emit_and_reset(h_pop, accept_states, accepted)
                candidates.append(h_pop)

            # Branch 2: DROP（丢弃该 node，不消费）
            h_drop = hypo.clone()
            h_drop.drops += 1
            h_drop.trace.append({"i": i, "decision": "DROP", "to_state": next_state.value})
            candidates.append(h_drop)

        # 4) 对 candidates 去重 + beam 截断，得到下一轮 active
        active = _dedup_and_beam(candidates, i=i, beam_width=beam_width)

    return accepted


def _extend_hypothesis(h: _Hypothesis, node: KillChainEdgeNode) -> None:
    """
    将 node 加入 hypothesis 的末段：
    - 若 state 变化，新建一个段
    - 否则追加到现有段
    """
    s = node.state
    if s is None:
        return
    if not h.segments or h.segments[-1].state != s:
        h.segments.append(_SegmentBuilder(state=s, nodes=[node]))
    else:
        h.segments[-1].nodes.append(node)


def _try_pop_until_accept(
    h: _Hypothesis,
    policy: TransitionPolicy,
    next_state: AttackState,
    max_pop_edges: int,
) -> bool:
    """
    POP 分支核心：
    - 尝试 pop 掉当前 hypothesis 的末尾若干 key edge
    - 直到能从新的 last_state 转到 next_state 或者 pop 到空

    返回：
    - True：找到可接入位置（h 被就地修改为回溯后的前缀）
    - False：pop 到上限仍不行（仍返回一次 _can_transition 的结果）
    """
    popped = 0
    while popped < max_pop_edges:
        if _can_transition(policy, h.last_state, next_state):
            return True

        # 已经空了：看 allow_start_anywhere 能否从 None 开始接入
        if not h.segments:
            return _can_transition(policy, None, next_state)

        # pop 段末尾一个 node；段空则移除段
        last_seg = h.segments[-1]
        last_seg.pop_one()
        popped += 1
        if not last_seg.nodes:
            h.segments.pop()

    # pop 到上限：返回当前是否可接入（通常是 False）
    return _can_transition(policy, h.last_state, next_state)


def _dedup_and_beam(candidates: List[_Hypothesis], *, i: int, beam_width: int) -> List[_Hypothesis]:
    """
    去重 + Beam 截断：

    dedup key = (i, last_state, last_anchor_out_uid)
    设计意图：
    - 同一位置、同一末状态、同一末锚点的 hypothesis 视为“等价”
    - 只保留 score_hint 更高的一条

    然后按 score_hint 逆序排序，截断到 beam_width。
    """
    best_by_key: Dict[Tuple[int, Optional[AttackState], Optional[str]], _Hypothesis] = {}

    for h in candidates:
        key = (i, h.last_state, h.last_anchor_out_uid)
        cur = best_by_key.get(key)
        if cur is None or h.score_hint > cur.score_hint:
            best_by_key[key] = h

    deduped = list(best_by_key.values())
    deduped.sort(key=lambda x: x.score_hint, reverse=True)

    return deduped[:beam_width] if beam_width > 0 else deduped


def _maybe_emit_and_reset(h: _Hypothesis, accept_states: Set[AttackState], out: List[FSAGraph]) -> None:
    """
    当 hypothesis 到达接受态时：
    - 输出一条 FSAGraph（包含 key nodes + trace）
    - 然后清空 hypothesis，继续寻找下一条链
    """
    if h.last_state is None or h.last_state not in accept_states:
        return

    nodes = h.flatten_nodes()
    if not nodes:
        return

    out.append(FSAGraph(nodes=list(nodes), trace=list(h.trace)))

    # 输出后清空（与之前 AttackFSA 的“输出后重置”一致）
    h.clear()


