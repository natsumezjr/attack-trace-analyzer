# attack_fsa.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Iterable
from datetime import datetime, timezone
from backend.graph.models import GraphEdge
from backend.graph.utils import _parse_ts_to_float

# =========================
# 1) 非可选 ATT&CK tactic 状态定义
# =========================

class AttackState(str, Enum):
# MITRE ATT&CK 标准战术名称（带空格格式，用于字符串比对）
    # 核心6个状态的标准格式
    INITIAL_ACCESS = "Initial Access"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    LATERAL_MOVEMENT = "Lateral Movement"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    EXECUTION = "Execution"
    
    # 其他 MITRE ATT&CK 战术（映射到最接近的核心状态）
    PERSISTENCE = "Persistence"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    COLLECTION = "Collection"
    IMPACT = "Impact"
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"


# =========================
# 2) 状态机：状态 -> 后驱状态列表（带注释说明）
# =========================

# 注：为了适应真实攻击链的“跳跃/缺失”，这里允许少量“跳状态”：
# - Execution 可能直接到 C2（落地后直接回连）
# - Execution/PrivEsc 可能直接到 Exfiltration（非常规但靶场可能出现）
# - LateralMovement 后可能在新主机再次 PrivEsc（常见）
STATE_TRANSITIONS: Dict[AttackState, Set[AttackState]] = {
    # InitialAccess：通常下一步是执行（用户打开附件/利用成功后开始执行）
    AttackState.INITIAL_ACCESS: {
        AttackState.EXECUTION,
    },

    # Execution：可能进入提权、横向、C2（或直接外传，属于跳跃）
    AttackState.EXECUTION: {
        AttackState.PRIVILEGE_ESCALATION,
        AttackState.LATERAL_MOVEMENT,
        AttackState.COMMAND_AND_CONTROL,
        AttackState.EXFILTRATION,  # allow skip
    },

    # PrivilegeEscalation：提权后通常横向或建立C2，也可能外传
    AttackState.PRIVILEGE_ESCALATION: {
        AttackState.LATERAL_MOVEMENT,
        AttackState.COMMAND_AND_CONTROL,
        AttackState.EXFILTRATION,  # allow skip
    },

    # LateralMovement：横向后可能在新主机再次执行/提权，也可能直接C2/外传
    AttackState.LATERAL_MOVEMENT: {
        AttackState.EXECUTION,             # 在新主机执行payload/远程执行
        AttackState.PRIVILEGE_ESCALATION,  # 在新主机提权
        AttackState.COMMAND_AND_CONTROL,
        AttackState.EXFILTRATION,
    },

    # C2：之后常见外传（也可能重复C2）
    AttackState.COMMAND_AND_CONTROL: {
        AttackState.EXFILTRATION,
    },

    # Exfiltration：在你们“非可选集合”中通常作为终止态（接受态）
    AttackState.EXFILTRATION: set(),
}

# 自环：同一阶段内会出现多条告警/异常边（例如连续多个 C2 beacon）
# 为避免“同一状态重复事件”导致频繁分支回溯，这里默认允许 self-loop。
ALLOW_SELF_LOOP: bool = True


# =========================
# 3) GraphEdge 的最小“鸭子类型”接口（避免强依赖你们的文件结构）
# =========================
class _EdgeLike:
    def get_attack_tag(self, edge: GraphEdge) -> Optional[str]:
        if hasattr(edge, "get_attack_tag"):
            return edge.get_attack_tag()
        else:
            raise NotImplementedError

    def get_ts(self, edge: GraphEdge) -> Optional[str]:
        if hasattr(edge, "get_ts"):
            return edge.get_ts()
        else:
            raise NotImplementedError


# =========================
# 4) 输出结构：状态转移图（路径）
# =========================
@dataclass
class TransitionStep:
    state: AttackState
    edge: _EdgeLike


@dataclass
class AttackPath:
    """
    一条被状态机接受的路径（可视为一条 killchain 骨架）：
    steps[i].edge 对应 steps[i].state 这一步的“异常边/证据边”
    """
    steps: List[TransitionStep]

    def states(self) -> List[AttackState]:
        return [s.state for s in self.steps]

    def edges(self) -> List[_EdgeLike]:
        return [s.edge for s in self.steps]

    def last_state(self) -> Optional[AttackState]:
        return self.steps[-1].state if self.steps else None




# =========================
# 6) tag -> state 映射（你们 props['attack_tag'] 应该落到这些值之一）
# =========================
TAG_TO_STATE: Dict[str, AttackState] = {
    # 你们内部推荐用：InitialAccess / Execution / PrivilegeEscalation / LateralMovement / CommandAndControl / Exfiltration
    "InitialAccess": AttackState.INITIAL_ACCESS,
    "Execution": AttackState.EXECUTION,
    "PrivilegeEscalation": AttackState.PRIVILEGE_ESCALATION,
    "LateralMovement": AttackState.LATERAL_MOVEMENT,
    "CommandAndControl": AttackState.COMMAND_AND_CONTROL,
    "Exfiltration": AttackState.EXFILTRATION,

    # 兼容 MITRE 常见空格写法（如果你们用的是 tactic.name）
    "Initial Access": AttackState.INITIAL_ACCESS,
    "Privilege Escalation": AttackState.PRIVILEGE_ESCALATION,
    "Lateral Movement": AttackState.LATERAL_MOVEMENT,
    "Command and Control": AttackState.COMMAND_AND_CONTROL,
}


def _edge_to_state(edge: _EdgeLike) -> Optional[AttackState]:
    tag = edge.get_attack_tag()
    if not tag:
        return None
    return TAG_TO_STATE.get(tag)


# =========================
# 7) 自动机类：当前状态、接受状态、状态转移函数、对外接口
# =========================
class AttackFSA:
    """
    你们要求的自动机：
      - current_state：当前状态（可为 None 表示未开始）
      - accept_states：接受状态集合（可通过接口添加/覆盖）
      - transition：状态转移判定
      - build_accepted_paths：对外接口（输入 error_edge_list，输出被接受的状态转移图列表）
      - branch/backtrack：当不能转移时，回溯 n 步直到能接受，否则丢弃
    """

    def __init__(
        self,
        accept_states: Optional[Set[AttackState]] = None,
        max_backtrack: int = 10,
    ) -> None:
        self.current_state: Optional[AttackState] = None
        self.accept_states: Set[AttackState] = accept_states or {AttackState.EXFILTRATION}
        self.max_backtrack = max_backtrack

    # ------- 接受状态接口（按你们要求留出） -------
    def add_accept_state(self, s: AttackState) -> None:
        self.accept_states.add(s)

    def set_accept_states(self, states: Set[AttackState]) -> None:
        self.accept_states = set(states)

    # ------- 转移判定 -------
    def can_transition(self, from_state: Optional[AttackState], to_state: AttackState) -> bool:
        # 起始：允许从任意状态开始（现实中经常缺 InitialAccess）
        if from_state is None:
            return True

        # 同一阶段多告警：允许自环
        if ALLOW_SELF_LOOP and to_state == from_state:
            return True

        return to_state in STATE_TRANSITIONS.get(from_state, set())

    # ------- 分支算法：回溯 n 步直到能接受，否则失败 -------
    def _try_backtrack(
        self,
        steps: List[TransitionStep],
        next_state: AttackState,
        n: int,
    ) -> bool:
        """
        回溯策略：最多 pop n 个 step，尝试找到一个能接 next_state 的位置。
        成功则返回 True（此时 steps 已被修改为回溯后的前缀）。
        """
        for _ in range(n):
            if not steps:
                break
            steps.pop()
            prev_state = steps[-1].state if steps else None
            if self.can_transition(prev_state, next_state):
                return True
        # 回溯完仍不行
        return False

    # ------- 对外接口：输入异常边列表，输出被接受的状态转移图列表 -------
    def build_accepted_paths(self, error_edge_list: List[_EdgeLike]) -> List[AttackPath]:
        """
        算法（按你描述）：
          1) 对 error_edge_list 按时间排序
          2) 逐条取边 -> 映射到 state
          3) 若可转移：append
             否则：调用分支回溯（最多回溯 max_backtrack）
                   若仍无法接受：丢弃该边（skip）
          4) 只有当路径到达 accept_states 才输出 AttackPath
             输出后重置当前路径（开始找下一条攻击链）
        """
        edges = sorted(error_edge_list, key=lambda e: _parse_ts_to_float(e.get_ts()))

        accepted: List[AttackPath] = []
        steps: List[TransitionStep] = []
        self.current_state = None

        for edge in edges:
            next_state = _edge_to_state(edge)
            if next_state is None:
                # 没有 attack_tag 或不在本状态机范围：直接跳过（不影响链）
                continue

            prev_state = steps[-1].state if steps else None

            if self.can_transition(prev_state, next_state):
                steps.append(TransitionStep(state=next_state, edge=edge))
            else:
                # 分支回溯：尝试回溯 n 步直到可接受
                ok = self._try_backtrack(steps, next_state, n=self.max_backtrack)
                if ok:
                    steps.append(TransitionStep(state=next_state, edge=edge))
                else:
                    # 仍无法接受：丢弃该边（按你要求）
                    continue

            # 只有到达接受状态才输出
            if steps and steps[-1].state in self.accept_states:
                accepted.append(AttackPath(steps=list(steps)))
                # 输出后重置，继续匹配下一条攻击链
                steps.clear()

        # 末尾如果没到接受状态，不输出（按你要求）
        return accepted
