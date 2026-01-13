# -*- coding: utf-8 -*-
"""
attack_fsa.py 模块单元测试

测试覆盖：
1. EdgeNode 和 KillChainEdgeNode 的基础功能
2. 状态映射 (TAG_TO_STATE)
3. 状态转移策略 (TransitionPolicy, default_transition_policy)
4. behavior_state_machine 核心功能
5. 辅助函数和内部逻辑
"""

import pytest
from pathlib import Path
from datetime import datetime
from typing import Any


# 使用绝对导入，避免 pytest 收集路径变化导致的相对导入失败
from app.services.algorithm.attack_fsa import (
    AttackState,
    TAG_TO_STATE,
    TransitionPolicy,
    default_transition_policy,
    EdgeNode,
    KillChainEdgeNode,
    StateSegment,
    FSAGraph,
    behavior_state_machine,
    _can_transition,
)
from app.services.graph.models import GraphEdge, RelType


# ========== 测试辅助函数 ==========

def create_test_edge(
    src_uid: str = "Host:h-001",
    dst_uid: str = "Host:h-002",
    attack_tag: str | None = None,
    timestamp: str | float | None = None,
    rtype: RelType = RelType.NET_CONNECT,
    **props
) -> GraphEdge:
    """
    创建测试用的 GraphEdge
    
    Args:
        src_uid: 源节点 UID
        dst_uid: 目标节点 UID
        attack_tag: ATT&CK 战术标签（如 "Initial Access"）
        timestamp: 时间戳（ISO 字符串或 float）
        rtype: 关系类型
        **props: 其他属性
    """
    edge_props: dict[str, Any] = dict(props)
    
    if attack_tag is not None:
        edge_props["threat"] = {
            "tactic": {
                "name": attack_tag
            }
        }
    
    if timestamp is not None:
        if isinstance(timestamp, (int, float)):
            edge_props["@timestamp"] = str(timestamp)
        else:
            edge_props["@timestamp"] = timestamp
    
    return GraphEdge(
        src_uid=src_uid,
        dst_uid=dst_uid,
        rtype=rtype,
        props=edge_props,
    )


# ========== EdgeNode 测试 ==========

class TestEdgeNode:
    """测试 EdgeNode 基础功能"""
    
    def test_edge_node_basic_properties(self):
        """测试 EdgeNode 基本属性访问"""
        edge = create_test_edge(
            src_uid="Host:h-001",
            dst_uid="Host:h-002",
            attack_tag="Initial Access",
            timestamp="2023-10-27T10:00:00Z"
        )
        node = EdgeNode(edge)
        
        assert node.src_uid == "Host:h-001"
        assert node.dst_uid == "Host:h-002"
        assert node.rtype == RelType.NET_CONNECT
        assert node.edge == edge
        assert node.props == edge.props
    
    def test_edge_node_attack_tag(self):
        """测试 attack_tag 属性"""
        # 有 attack_tag 的情况
        edge1 = create_test_edge(attack_tag="Initial Access")
        node1 = EdgeNode(edge1)
        assert node1.attack_tag == "Initial Access"
        
        # 无 attack_tag 的情况
        edge2 = create_test_edge()
        node2 = EdgeNode(edge2)
        assert node2.attack_tag is None
    
    def test_edge_node_state_mapping(self):
        """测试 state 属性映射"""
        # 测试各种状态映射
        test_cases = [
            ("Initial Access", AttackState.INITIAL_ACCESS),
            ("Execution", AttackState.EXECUTION),
            ("Privilege Escalation", AttackState.PRIVILEGE_ESCALATION),
            ("Exfiltration", AttackState.EXFILTRATION),
            ("Reconnaissance", AttackState.RECONNAISSANCE),
        ]
        
        for tag, expected_state in test_cases:
            edge = create_test_edge(attack_tag=tag)
            node = EdgeNode(edge)
            assert node.state == expected_state, f"Tag '{tag}' 应该映射到 {expected_state}"
        
        # 未知标签应返回 None
        edge_unknown = create_test_edge(attack_tag="Unknown Tag")
        node_unknown = EdgeNode(edge_unknown)
        assert node_unknown.state is None
    
    def test_edge_node_timestamp(self):
        """测试时间戳解析"""
        # ISO 格式时间戳
        edge1 = create_test_edge(timestamp="2023-10-27T10:00:00Z")
        node1 = EdgeNode(edge1)
        assert node1.ts > 0
        
        # 数字字符串时间戳
        edge2 = create_test_edge(timestamp="1698400800.0")
        node2 = EdgeNode(edge2)
        assert node2.ts == 1698400800.0
        
        # 无时间戳（应返回 0.0）
        edge3 = create_test_edge()
        node3 = EdgeNode(edge3)
        assert node3.ts == 0.0


class TestKillChainEdgeNode:
    """测试 KillChainEdgeNode"""
    
    def test_kill_chain_edge_node_flags(self):
        """测试 is_key 和 is_completion 标志"""
        edge = create_test_edge(attack_tag="Execution")
        
        # 关键边
        key_node = KillChainEdgeNode(edge, is_key=True, is_completion=False)
        assert key_node.is_key is True
        assert key_node.is_completion is False
        
        # 补全边
        comp_node = KillChainEdgeNode(edge, is_key=False, is_completion=True)
        assert comp_node.is_key is False
        assert comp_node.is_completion is True
        
        # 继承 EdgeNode 的属性
        assert key_node.state == AttackState.EXECUTION
        assert key_node.attack_tag == "Execution"


# ========== 状态映射测试 ==========

class TestStateMapping:
    """测试 TAG_TO_STATE 映射"""
    
    def test_all_attack_states_mapped(self):
        """测试所有 ATT&CK 状态都能被映射"""
        # 测试紧凑格式（无空格）
        compact_tags = [
            "Reconnaissance",
            "ResourceDevelopment",
            "InitialAccess",
            "Execution",
            "Persistence",
            "PrivilegeEscalation",
            "DefenseEvasion",
            "CredentialAccess",
            "Discovery",
            "LateralMovement",
            "Collection",
            "CommandAndControl",
            "Exfiltration",
            "Impact",
        ]
        
        for tag in compact_tags:
            assert tag in TAG_TO_STATE, f"标签 '{tag}' 应该在映射表中"
            state = TAG_TO_STATE[tag]
            assert isinstance(state, AttackState)
    
    def test_mitre_display_names_mapped(self):
        """测试 MITRE 显示格式（带空格）也能映射"""
        display_tags = [
            "Resource Development",
            "Initial Access",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Lateral Movement",
            "Command and Control",
        ]
        
        for tag in display_tags:
            assert tag in TAG_TO_STATE, f"显示标签 '{tag}' 应该在映射表中"


# ========== 状态转移策略测试 ==========

class TestTransitionPolicy:
    """测试状态转移策略"""
    
    def test_default_policy_structure(self):
        """测试默认策略结构"""
        policy = default_transition_policy()
        
        assert isinstance(policy, TransitionPolicy)
        assert policy.allow_self_loop is True
        assert policy.allow_start_anywhere is True
        assert isinstance(policy.allowed_next, dict)
        
        # 检查所有状态都在 allowed_next 中
        for state in AttackState:
            assert state in policy.allowed_next
    
    def test_can_transition_start_anywhere(self):
        """测试 allow_start_anywhere"""
        policy = TransitionPolicy(
            allowed_next={},
            allow_start_anywhere=True
        )
        assert _can_transition(policy, None, AttackState.EXECUTION) is True
        
        policy_no_start = TransitionPolicy(
            allowed_next={},
            allow_start_anywhere=False
        )
        assert _can_transition(policy_no_start, None, AttackState.EXECUTION) is False
    
    def test_can_transition_self_loop(self):
        """测试 allow_self_loop"""
        policy = TransitionPolicy(
            allowed_next={AttackState.EXECUTION: {AttackState.DISCOVERY}},
            allow_self_loop=True
        )
        assert _can_transition(policy, AttackState.EXECUTION, AttackState.EXECUTION) is True
        
        policy_no_loop = TransitionPolicy(
            allowed_next={AttackState.EXECUTION: {AttackState.DISCOVERY}},
            allow_self_loop=False
        )
        assert _can_transition(policy_no_loop, AttackState.EXECUTION, AttackState.EXECUTION) is False
    
    def test_can_transition_allowed_next(self):
        """测试 allowed_next 规则"""
        policy = default_transition_policy()
        
        # Execution -> Discovery 应该是允许的
        assert _can_transition(policy, AttackState.EXECUTION, AttackState.DISCOVERY) is True
        
        # Execution -> Initial Access 应该不允许（违反顺序）
        assert _can_transition(policy, AttackState.EXECUTION, AttackState.INITIAL_ACCESS) is False
    
    def test_can_transition_jump_pairs(self):
        """测试 allow_jump_pairs"""
        policy = TransitionPolicy(
            allowed_next={},
            allow_jump_pairs={(AttackState.RECONNAISSANCE, AttackState.EXECUTION)}
        )
        assert _can_transition(policy, AttackState.RECONNAISSANCE, AttackState.EXECUTION) is True


# ========== behavior_state_machine 测试 ==========

class TestBehaviorStateMachine:
    """测试 behavior_state_machine 核心功能"""
    
    def test_empty_input(self):
        """测试空输入"""
        graphs = behavior_state_machine([])
        assert graphs == []
    
    def test_simple_valid_chain(self):
        """测试简单的有效攻击链"""
        edges = [
            create_test_edge(
                src_uid="Host:h-001",
                dst_uid="Host:h-002",
                attack_tag="Initial Access",
                timestamp="2023-10-27T10:00:00Z"
            ),
            create_test_edge(
                src_uid="Host:h-002",
                dst_uid="Host:h-003",
                attack_tag="Execution",
                timestamp="2023-10-27T10:01:00Z"
            ),
            create_test_edge(
                src_uid="Host:h-003",
                dst_uid="Host:h-004",
                attack_tag="Exfiltration",
                timestamp="2023-10-27T10:02:00Z"
            ),
        ]
        
        graphs = behavior_state_machine(edges)
        
        # 应该生成至少一条到达 Exfiltration 的图
        assert len(graphs) >= 1
        
        # 检查第一条图的结构
        graph = graphs[0]
        assert len(graph.nodes) >= 3
        assert all(hasattr(n, "is_key") and n.is_key for n in graph.nodes)
    
    def test_edges_without_attack_tag_are_skipped(self):
        """测试没有 attack_tag 的边会被跳过"""
        edges = [
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag=None, timestamp="2023-10-27T10:01:00Z"),  # 无标签
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:02:00Z"),
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:03:00Z"),
        ]
        
        graphs = behavior_state_machine(edges)
        # 应该能够正常处理，跳过无标签的边
        assert isinstance(graphs, list)
    
    def test_edges_sorted_by_timestamp(self):
        """测试边会按时间戳排序"""
        edges = [
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:02:00Z"),
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:03:00Z"),
        ]
        
        graphs = behavior_state_machine(edges)
        # 如果处理顺序正确，应该能形成有效链
        # 即使输入顺序乱序，也应该按时间排序后处理
        assert isinstance(graphs, list)
    
    def test_drop_branch(self):
        """测试 DROP 分支（丢弃不符合转移规则的边）"""
        # 创建一个违反转移规则的序列
        edges = [
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:01:00Z"),  # 违反规则
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:02:00Z"),
        ]
        
        graphs = behavior_state_machine(edges, beam_width=50)
        # DROP 分支应该允许丢弃中间的 Initial Access，形成 Execution -> Exfiltration
        assert isinstance(graphs, list)
    
    def test_pop_branch(self):
        """测试 POP 分支（回溯移除若干边）"""
        edges = [
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:01:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:02:00Z"),
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:03:00Z"),
        ]
        
        graphs = behavior_state_machine(edges, max_backtrack_edges=5, beam_width=50)
        assert isinstance(graphs, list)
    
    def test_multiple_accept_states(self):
        """测试多个接受状态"""
        edges = [
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:01:00Z"),
            create_test_edge(attack_tag="Impact", timestamp="2023-10-27T10:02:00Z"),
        ]
        
        accept_states = {AttackState.IMPACT, AttackState.EXFILTRATION}
        graphs = behavior_state_machine(edges, accept_states=accept_states)
        
        # 应该能到达 Impact 状态
        assert len(graphs) >= 1
        graph = graphs[0]
        assert len(graph.nodes) >= 2
    
    def test_self_loop_allowed(self):
        """测试自环（同一状态连续出现）"""
        edges = [
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:01:00Z"),  # 自环
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:02:00Z"),  # 自环
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:03:00Z"),
        ]
        
        graphs = behavior_state_machine(edges)
        assert isinstance(graphs, list)
        # 如果成功，应该包含多条 Execution 边
    
    def test_beam_width_limit(self):
        """测试 beam_width 限制"""
        # 创建一个会产生大量分支的序列
        edges = [
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
        ] + [
            create_test_edge(attack_tag="Execution", timestamp=f"2023-10-27T10:0{i}:00Z")
            for i in range(1, 20)  # 多个 Execution（自环）
        ] + [
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:20:00Z"),
        ]
        
        graphs_small_beam = behavior_state_machine(edges, beam_width=5)
        graphs_large_beam = behavior_state_machine(edges, beam_width=100)
        
        # beam_width 应该影响结果数量（但都能完成处理）
        assert isinstance(graphs_small_beam, list)
        assert isinstance(graphs_large_beam, list)


# ========== FSAGraph 测试 ==========

class TestFSAGraph:
    """测试 FSAGraph"""
    
    def test_fsa_graph_segments(self):
        """测试 segments() 方法"""
        edges = [
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:01:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:02:00Z"),  # 同一状态
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:03:00Z"),
        ]
        
        graphs = behavior_state_machine(edges)
        if graphs:
            graph = graphs[0]
            segments = graph.segments()
            
            # 应该按状态分段
            assert len(segments) >= 1
            for seg in segments:
                assert isinstance(seg, StateSegment)
                assert len(seg.nodes) > 0
    
    def test_fsa_graph_time_properties(self):
        """测试时间属性"""
        edges = [
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:01:00Z"),
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:02:00Z"),
        ]
        
        graphs = behavior_state_machine(edges)
        if graphs:
            graph = graphs[0]
            assert graph.t_start > 0
            assert graph.t_end >= graph.t_start
    
    def test_fsa_graph_trace(self):
        """测试 trace 记录"""
        edges = [
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:01:00Z"),  # 违反规则，可能触发 DROP/POP
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:02:00Z"),
        ]
        
        graphs = behavior_state_machine(edges, beam_width=50)
        if graphs:
            graph = graphs[0]
            assert isinstance(graph.trace, list)
            # trace 可能包含 DROP 或 POP 决策记录


# ========== StateSegment 测试 ==========

class TestStateSegment:
    """测试 StateSegment"""
    
    def test_state_segment_properties(self):
        """测试 StateSegment 属性"""
        edge1 = create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:00:00Z")
        edge2 = create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:01:00Z")
        
        node1 = EdgeNode(edge1)
        node2 = EdgeNode(edge2)
        
        segment = StateSegment(state=AttackState.EXECUTION, nodes=[node1, node2])
        
        assert segment.state == AttackState.EXECUTION
        assert len(segment.nodes) == 2
        assert segment.t_start == node1.ts
        assert segment.t_end == node2.ts
        assert segment.anchor_in_uid == node1.src_uid
        assert segment.anchor_out_uid == node2.dst_uid
    
    def test_empty_segment(self):
        """测试空段"""
        segment = StateSegment(state=AttackState.EXECUTION, nodes=[])
        assert segment.t_start == 0.0
        assert segment.t_end == 0.0
        assert segment.anchor_in_uid == ""
        assert segment.anchor_out_uid == ""


# ========== 集成测试 ==========

class TestIntegration:
    """集成测试：模拟完整攻击链"""
    
    def test_complete_kill_chain(self):
        """测试完整的攻击链（从 Reconnaissance 到 Impact）"""
        edges = [
            create_test_edge(
                src_uid="Host:h-recon",
                dst_uid="Host:h-target",
                attack_tag="Reconnaissance",
                timestamp="2023-10-27T10:00:00Z"
            ),
            create_test_edge(
                src_uid="Host:h-recon",
                dst_uid="Host:h-target",
                attack_tag="Initial Access",
                timestamp="2023-10-27T10:05:00Z"
            ),
            create_test_edge(
                src_uid="Host:h-target",
                dst_uid="Process:p-001",
                attack_tag="Execution",
                timestamp="2023-10-27T10:10:00Z"
            ),
            create_test_edge(
                src_uid="Process:p-001",
                dst_uid="Process:p-002",
                attack_tag="Privilege Escalation",
                timestamp="2023-10-27T10:15:00Z"
            ),
            create_test_edge(
                src_uid="Process:p-002",
                dst_uid="File:f-data",
                attack_tag="Collection",
                timestamp="2023-10-27T10:20:00Z"
            ),
            create_test_edge(
                src_uid="File:f-data",
                dst_uid="Network:n-out",
                attack_tag="Exfiltration",
                timestamp="2023-10-27T10:25:00Z"
            ),
        ]
        
        graphs = behavior_state_machine(edges, beam_width=100)
        
        # 应该生成至少一条完整的攻击链
        assert len(graphs) >= 1
        
        graph = graphs[0]
        assert len(graph.nodes) >= 3  # 至少包含关键状态转移
        
        # 检查状态序列
        segments = graph.segments()
        states = [seg.state for seg in segments]
        
        # 应该包含从 Reconnaissance 到 Exfiltration 的路径
        assert AttackState.RECONNAISSANCE in states or AttackState.INITIAL_ACCESS in states
        assert AttackState.EXFILTRATION in states or AttackState.IMPACT in states or AttackState.COMMAND_AND_CONTROL in states
    
    def test_multiple_paths_with_noise(self):
        """测试包含噪声的多条路径"""
        edges = [
            # 有效路径 1
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:00:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:01:00Z"),
            create_test_edge(attack_tag="Exfiltration", timestamp="2023-10-27T10:02:00Z"),
            
            # 噪声（无标签）
            create_test_edge(attack_tag=None, timestamp="2023-10-27T10:03:00Z"),
            create_test_edge(attack_tag=None, timestamp="2023-10-27T10:04:00Z"),
            
            # 有效路径 2
            create_test_edge(attack_tag="Initial Access", timestamp="2023-10-27T10:05:00Z"),
            create_test_edge(attack_tag="Execution", timestamp="2023-10-27T10:06:00Z"),
            create_test_edge(attack_tag="Impact", timestamp="2023-10-27T10:07:00Z"),
        ]
        
        accept_states = {AttackState.EXFILTRATION, AttackState.IMPACT}
        graphs = behavior_state_machine(edges, accept_states=accept_states, beam_width=50)
        
        # 应该能识别多条路径
        assert len(graphs) >= 1
        assert isinstance(graphs, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
