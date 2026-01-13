from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from backend.graph.models import GraphEdge
from backend.graph.utils import _parse_ts_to_float


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
    """Finite-state transition policy."""

    allowed_next: Dict[AttackState, Set[AttackState]]
    allow_self_loop: bool = True
    allow_start_anywhere: bool = True
    # Optional knobs
    max_state_skip: Optional[int] = None
    allow_jump_pairs: Set[Tuple[AttackState, AttackState]] = field(default_factory=set)


def default_transition_policy() -> TransitionPolicy:
    """A reasonable default transition policy for 14 ATT&CK tactics."""
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
    """不要改字段：只通过 property 暴露。"""

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
        return _parse_ts_to_float(self._edge.get_ts() if hasattr(self._edge, "get_ts") else None)

    @property
    def attack_tag(self) -> Optional[str]:
        return self._edge.get_attack_tag() if hasattr(self._edge, "get_attack_tag") else None

    @property
    def state(self) -> Optional[AttackState]:
        tag = self.attack_tag
        if not tag:
            return None
        return TAG_TO_STATE.get(tag)


class KillChainEdgeNode(EdgeNode):
    """子类加字段（允许）：标识 key / completion。"""

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
        return self.nodes[0].src_uid if self.nodes else ""

    @property
    def anchor_out_uid(self) -> str:
        return self.nodes[-1].dst_uid if self.nodes else ""


@dataclass(slots=True)
class FSAGraph:
    nodes: List[EdgeNode]
    trace: List[Dict[str, Any]] = field(default_factory=list)

    def segments(self) -> List[StateSegment]:
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


@dataclass(slots=True)
class _SegmentBuilder:
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
    segments: List[_SegmentBuilder] = field(default_factory=list)
    drops: int = 0
    pops: int = 0
    trace: List[Dict[str, Any]] = field(default_factory=list)

    def clone(self) -> "_Hypothesis":
        segs: List[_SegmentBuilder] = []
        for seg in self.segments:
            segs.append(_SegmentBuilder(state=seg.state, nodes=list(seg.nodes)))
        return _Hypothesis(segments=segs, drops=self.drops, pops=self.pops, trace=list(self.trace))

    @property
    def last_state(self) -> Optional[AttackState]:
        return self.segments[-1].state if self.segments else None

    @property
    def last_anchor_out_uid(self) -> Optional[str]:
        if not self.segments:
            return None
        ln = self.segments[-1].last_node
        return ln.dst_uid if ln else None

    @property
    def key_edge_count(self) -> int:
        return sum(len(seg.nodes) for seg in self.segments)

    @property
    def score_hint(self) -> float:
        return float(self.key_edge_count) - 0.25 * float(self.drops) - 0.5 * float(self.pops)

    def flatten_nodes(self) -> List[KillChainEdgeNode]:
        out: List[KillChainEdgeNode] = []
        for seg in self.segments:
            out.extend(seg.nodes)
        return out

    def clear(self) -> None:
        self.segments.clear()
        self.drops = 0
        self.pops = 0
        self.trace.clear()


def _can_transition(policy: TransitionPolicy, from_state: Optional[AttackState], to_state: AttackState) -> bool:
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
    if policy is None:
        policy = default_transition_policy()
    if accept_states is None:
        accept_states = {AttackState.EXFILTRATION}

    edges_sorted = sorted(abnormal_edges, key=lambda e: _parse_ts_to_float(e.get_ts() if hasattr(e, "get_ts") else None))

    nodes: List[KillChainEdgeNode] = []
    for e in edges_sorted:
        n = KillChainEdgeNode(e, is_key=True, is_completion=False)
        if n.state is None:
            continue
        nodes.append(n)

    accepted: List[FSAGraph] = []
    active: List[_Hypothesis] = [_Hypothesis()]

    for i, node in enumerate(nodes):
        next_state = node.state
        if next_state is None:
            continue

        candidates: List[_Hypothesis] = []

        for hypo in active:
            prev_state = hypo.last_state

            if _can_transition(policy, prev_state, next_state):
                h = hypo.clone()
                _extend_hypothesis(h, node)
                _maybe_emit_and_reset(h, accept_states, accepted)
                candidates.append(h)
                continue

            # Branch 1: POP
            h_pop = hypo.clone()
            ok = _try_pop_until_accept(h_pop, policy, next_state, max_backtrack_edges)
            if ok:
                h_pop.pops += 1
                h_pop.trace.append({"i": i, "decision": "POP", "to_state": next_state.value})
                _extend_hypothesis(h_pop, node)
                _maybe_emit_and_reset(h_pop, accept_states, accepted)
                candidates.append(h_pop)

            # Branch 2: DROP
            h_drop = hypo.clone()
            h_drop.drops += 1
            h_drop.trace.append({"i": i, "decision": "DROP", "to_state": next_state.value})
            candidates.append(h_drop)

        active = _dedup_and_beam(candidates, i=i, beam_width=beam_width)

    return accepted


def _extend_hypothesis(h: _Hypothesis, node: KillChainEdgeNode) -> None:
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
    popped = 0
    while popped < max_pop_edges:
        if _can_transition(policy, h.last_state, next_state):
            return True
        if not h.segments:
            return _can_transition(policy, None, next_state)

        last_seg = h.segments[-1]
        last_seg.pop_one()
        popped += 1
        if not last_seg.nodes:
            h.segments.pop()

    return _can_transition(policy, h.last_state, next_state)


def _dedup_and_beam(candidates: List[_Hypothesis], *, i: int, beam_width: int) -> List[_Hypothesis]:
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
    if h.last_state is None or h.last_state not in accept_states:
        return
    nodes = h.flatten_nodes()
    if not nodes:
        return
    out.append(FSAGraph(nodes=list(nodes), trace=list(h.trace)))
    h.clear()
