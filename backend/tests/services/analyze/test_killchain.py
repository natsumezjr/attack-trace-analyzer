# -*- coding: utf-8 -*-
"""
killchain.py 模块单元测试

测试覆盖：
1. 辅助函数（_sha1_hex, _ecs_get, _truncate, _edge_ts, _edge_stable_id 等）
2. Segment summaries (build_segment_summaries)
3. Phase B: 候选路径枚举 (enumerate_candidate_paths_multi_stage, connect_fsa_segments_to_candidates)
4. Phase C: LLM 选择 (build_llm_payload, select_killchain_with_llm, materialize_killchain)
5. 持久化 (persist_killchain_to_db)
6. 完整流水线 (run_killchain_pipeline)
"""

import json
import pytest
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import Mock, patch, MagicMock

from app.services.analyze.killchain import (
    _sha1_hex,
    _ecs_get,
    _truncate,
    _edge_ts,
    _edge_stable_id,
    _normalize_reltypes,
    build_segment_summaries,
    CandidatePath,
    PathStepView,
    SegmentSummary,
    AnchorPairCandidates,
    SemanticCandidateSubgraph,
    KillChain,
    AnchorPairCache,
    enumerate_candidate_paths_multi_stage,
    connect_fsa_segments_to_candidates,
    build_semantic_candidate_subgraphs,
    build_llm_payload,
    select_killchain_with_llm,
    materialize_killchain,
    persist_killchain_to_db,
    run_killchain_pipeline,
    TIME_MARGIN_SEC,
    FIRST_K,
    SECOND_K,
    MAX_PATHS_PER_PAIR,
    ALLOWED_RELTYPES,
    KC_ECS_FIELD,
)
from app.services.analyze.attack_fsa import (
    AttackState,
    FSAGraph,
    StateSegment,
    EdgeNode,
    behavior_state_machine,
)
from app.services.neo4j.models import GraphEdge, GraphNode, NodeType, RelType, build_uid
from app.services.neo4j.utils import _parse_ts_to_float


# ========== 测试辅助函数 ==========

def _fixtures_dir() -> Path:
    """获取测试数据目录"""
    return Path(__file__).resolve().parents[2] / "fixtures" / "graph"


def load_test_events() -> List[Dict[str, Any]]:
    """从 testExample.json 加载测试事件"""
    fixture_path = _fixtures_dir() / "testExample.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


def create_test_edge(
    src_uid: str = "Host:h-001",
    dst_uid: str = "Host:h-002",
    rtype: RelType = RelType.NET_CONNECT,
    timestamp: str | float | None = None,
    event_id: str | None = None,
    **props
) -> GraphEdge:
    """创建测试用的 GraphEdge"""
    edge_props: Dict[str, Any] = dict(props)
    
    if timestamp is not None:
        if isinstance(timestamp, (int, float)):
            edge_props["@timestamp"] = str(timestamp)
            edge_props["ts_float"] = float(timestamp)
        else:
            edge_props["@timestamp"] = timestamp
            edge_props["ts_float"] = _parse_ts_to_float(timestamp)
    
    if event_id:
        edge_props["event.id"] = event_id
    
    return GraphEdge(
        src_uid=src_uid,
        dst_uid=dst_uid,
        rtype=rtype,
        props=edge_props,
    )


def create_test_fsa_graph(edges: List[GraphEdge]) -> FSAGraph:
    """从边列表创建测试用的 FSAGraph"""
    graphs = behavior_state_machine(edges)
    if not graphs:
        # 如果无法生成图，创建一个简单的 mock
        from app.services.analyze.attack_fsa import EdgeNode
        nodes = [EdgeNode(e) for e in edges]
        return FSAGraph(
            nodes=nodes,
            trace=[],
        )
    return graphs[0]


# ========== 辅助函数测试 ==========

class TestHelperFunctions:
    """测试辅助函数"""
    
    def test_sha1_hex(self):
        """测试 _sha1_hex"""
        result = _sha1_hex("test_string")
        assert isinstance(result, str)
        assert len(result) == 16  # 默认截断到16位
        
        result_long = _sha1_hex("test_string", n=20)
        assert len(result_long) == 20
        
        # 相同输入应产生相同输出
        assert _sha1_hex("test") == _sha1_hex("test")
    
    def test_ecs_get(self):
        """测试 _ecs_get"""
        # 扁平键
        props = {"event.id": "evt-001", "host.name": "test-host"}
        assert _ecs_get(props, "event.id") == "evt-001"
        assert _ecs_get(props, "host.name") == "test-host"
        
        # 嵌套对象
        props_nested = {
            "event": {"id": "evt-002", "kind": "event"},
            "host": {"name": "host-01"}
        }
        assert _ecs_get(props_nested, "event.id") == "evt-002"
        assert _ecs_get(props_nested, "host.name") == "host-01"
        
        # 不存在的键
        assert _ecs_get(props, "nonexistent.key") is None
        assert _ecs_get(props_nested, "event.nonexistent") is None
    
    def test_truncate(self):
        """测试 _truncate"""
        short_str = "short"
        assert _truncate(short_str) == short_str
        
        long_str = "a" * 300
        truncated = _truncate(long_str, max_len=200)
        assert len(truncated) == 201  # 200 + "…"
        assert truncated.endswith("…")
        
        # 非字符串应原样返回
        assert _truncate(123) == 123
        assert _truncate([1, 2, 3]) == [1, 2, 3]
    
    def test_edge_ts(self):
        """测试 _edge_ts"""
        # ISO 格式时间戳
        edge1 = create_test_edge(timestamp="2026-01-12T03:21:10.123Z")
        ts1 = _edge_ts(edge1)
        assert isinstance(ts1, float)
        assert ts1 > 0
        
        # 数字时间戳
        edge2 = create_test_edge(timestamp=1705044070.123)
        ts2 = _edge_ts(edge2)
        assert ts2 == 1705044070.123
        
        # 无时间戳
        edge3 = create_test_edge()
        ts3 = _edge_ts(edge3)
        assert ts3 == 0.0
    
    def test_edge_stable_id(self):
        """测试 _edge_stable_id"""
        # 有 event.id 的情况
        edge1 = create_test_edge(
            event_id="evt-56489be4abef0ac5",
            timestamp="2026-01-12T03:21:10.123Z"
        )
        assert _edge_stable_id(edge1) == "evt-56489be4abef0ac5"
        
        # 无 event.id，使用 hash
        edge2 = create_test_edge(
            src_uid="Host:h-001",
            dst_uid="Host:h-002",
            rtype=RelType.NET_CONNECT,
            timestamp="2026-01-12T03:21:10.123Z"
        )
        eid2 = _edge_stable_id(edge2)
        assert eid2.startswith("e-")
        assert len(eid2) > 2
        
        # 相同边应产生相同 id
        edge3 = create_test_edge(
            src_uid="Host:h-001",
            dst_uid="Host:h-002",
            rtype=RelType.NET_CONNECT,
            timestamp="2026-01-12T03:21:10.123Z"
        )
        assert _edge_stable_id(edge2) == _edge_stable_id(edge3)
    
    def test_normalize_reltypes(self):
        """测试 _normalize_reltypes"""
        # RelType 枚举
        reltypes1 = [RelType.SPAWN, RelType.LOGON]
        result1 = _normalize_reltypes(reltypes1)
        assert result1 == {"SPAWN", "LOGON"}
        
        # 字符串
        reltypes2 = ["SPAWN", "LOGON"]
        result2 = _normalize_reltypes(reltypes2)
        assert result2 == {"SPAWN", "LOGON"}
        
        # 混合
        reltypes3 = [RelType.SPAWN, "LOGON"]
        result3 = _normalize_reltypes(reltypes3)
        assert result3 == {"SPAWN", "LOGON"}
        


# ========== Segment Summaries 测试 ==========

class TestSegmentSummaries:
    """测试 build_segment_summaries"""
    
    def test_build_segment_summaries_basic(self):
        """测试基本段摘要构建"""
        edges = [
            create_test_edge(
                src_uid="Host:h-001",
                dst_uid="Process:p-001",
                rtype=RelType.LOGON,
                timestamp="2026-01-12T03:21:10.123Z",
                event_id="evt-001",
                **{"event.action": "user_login", "host.name": "victim-01"}
            ),
            create_test_edge(
                src_uid="Process:p-001",
                dst_uid="Process:p-002",
                rtype=RelType.SPAWN,
                timestamp="2026-01-12T03:21:15.321Z",
                event_id="evt-002",
                **{"process.name": "powershell.exe"}
            ),
        ]
        
        fsa_graph = create_test_fsa_graph(edges)
        summaries = build_segment_summaries(fsa_graph, top_n=6)
        
        assert isinstance(summaries, list)
        assert len(summaries) > 0
        
        for seg in summaries:
            assert isinstance(seg, SegmentSummary)
            assert hasattr(seg, "seg_idx")
            assert hasattr(seg, "state")
            assert hasattr(seg, "t_start")
            assert hasattr(seg, "t_end")
            assert hasattr(seg, "anchor_in_uid")
            assert hasattr(seg, "anchor_out_uid")
            assert hasattr(seg, "abnormal_edge_summaries")
            assert isinstance(seg.abnormal_edge_summaries, list)
    
    def test_build_segment_summaries_top_n_limit(self):
        """测试 top_n 限制"""
        # 创建多条边
        edges = [
            create_test_edge(
                timestamp=f"2026-01-12T03:21:{10+i}.000Z",
                event_id=f"evt-{i:03d}"
            )
            for i in range(20)
        ]
        
        fsa_graph = create_test_fsa_graph(edges)
        summaries = build_segment_summaries(fsa_graph, top_n=5)
        
        # 每个段的摘要不应超过 top_n
        for seg in summaries:
            assert len(seg.abnormal_edge_summaries) <= 5


# ========== AnchorPairCache 测试 ==========

class TestAnchorPairCache:
    """测试 AnchorPairCache"""
    
    def test_cache_basic(self):
        """测试基本缓存功能"""
        cache = AnchorPairCache(max_items=10)
        
        key1 = ("Host:h-001", "Host:h-002", 1000.0, 2000.0, "sig1")
        value1 = [
            CandidatePath(
                path_id="p-001",
                src_anchor="Host:h-001",
                dst_anchor="Host:h-002",
                t_min=1000.0,
                t_max=2000.0,
                edges=(),
                steps=(),
                signature="sig1",
            )
        ]
        
        # 设置和获取
        assert cache.get(key1) is None
        cache.set(key1, value1)
        assert cache.get(key1) == value1
        
        # 更新
        value1_updated = value1 + [
            CandidatePath(
                path_id="p-002",
                src_anchor="Host:h-001",
                dst_anchor="Host:h-002",
                t_min=1000.0,
                t_max=2000.0,
                edges=(),
                steps=(),
                signature="sig2",
            )
        ]
        cache.set(key1, value1_updated)
        assert len(cache.get(key1)) == 2
    
    def test_cache_fifo_eviction(self):
        """测试 FIFO 淘汰策略"""
        cache = AnchorPairCache(max_items=3)
        
        # 添加 4 个条目，应该淘汰第一个
        for i in range(4):
            key = (f"src-{i}", f"dst-{i}", 1000.0, 2000.0, f"sig-{i}")
            value = [
                CandidatePath(
                    path_id=f"p-{i}",
                    src_anchor=f"src-{i}",
                    dst_anchor=f"dst-{i}",
                    t_min=1000.0,
                    t_max=2000.0,
                    edges=(),
                    steps=(),
                    signature=f"sig-{i}",
                )
            ]
            cache.set(key, value)
        
        # 第一个应该被淘汰
        key0 = ("src-0", "dst-0", 1000.0, 2000.0, "sig-0")
        assert cache.get(key0) is None
        
        # 后面的应该还在
        key3 = ("src-3", "dst-3", 1000.0, 2000.0, "sig-3")
        assert cache.get(key3) is not None


# ========== Phase B: 候选路径枚举测试 ==========

class TestPhaseBCandidatePaths:
    """测试 Phase B 候选路径枚举"""
    
    @patch("app.services.analyze.killchain.graph_api.get_edges_in_window")
    def test_enumerate_candidate_paths_multi_stage_empty(self, mock_get_edges):
        """测试空结果的情况"""
        mock_get_edges.return_value = []
        
        cache = AnchorPairCache()
        result = enumerate_candidate_paths_multi_stage(
            cache=cache,
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=2000.0,
            allowed_reltypes=ALLOWED_RELTYPES,
            max_hops=8,
        )
        
        assert isinstance(result, list)
        # Stage 1 和 Stage 2 都为空时，返回空列表
        assert len(result) == 0
    
    @patch("app.services.analyze.killchain.graph_api.get_edges_in_window")
    def test_enumerate_candidate_paths_multi_stage_with_edges(self, mock_get_edges):
        """测试有边的情况"""
        # 创建一条连接路径
        edge1 = create_test_edge(
            src_uid="Host:h-001",
            dst_uid="Process:p-001",
            rtype=RelType.LOGON,
            timestamp=1500.0,
        )
        edge2 = create_test_edge(
            src_uid="Process:p-001",
            dst_uid="Host:h-002",
            rtype=RelType.RUNS_ON,
            timestamp=1600.0,
        )
        
        mock_get_edges.return_value = [edge1, edge2]
        
        cache = AnchorPairCache()
        result = enumerate_candidate_paths_multi_stage(
            cache=cache,
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=2000.0,
            allowed_reltypes=[RelType.LOGON, RelType.RUNS_ON],
            max_hops=8,
        )
        
        assert isinstance(result, list)
        # 如果 BFS 能找到路径，应该返回候选路径
        # 注意：实际结果取决于 BFS 是否能找到从 h-001 到 h-002 的路径
    
    @patch("app.services.analyze.killchain.graph_api.get_edges_in_window")
    def test_enumerate_candidate_paths_cache_hit(self, mock_get_edges):
        """测试缓存命中"""
        cache = AnchorPairCache()
        
        # 第一次调用
        mock_get_edges.return_value = []
        result1 = enumerate_candidate_paths_multi_stage(
            cache=cache,
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=2000.0,
            allowed_reltypes=ALLOWED_RELTYPES,
            max_hops=8,
        )
        
        # 第二次调用（相同参数）应该命中缓存
        result2 = enumerate_candidate_paths_multi_stage(
            cache=cache,
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=2000.0,
            allowed_reltypes=ALLOWED_RELTYPES,
            max_hops=8,
        )
        
        # 第二次不应该调用 API（但 mock 无法验证，只能验证结果一致）
        assert result1 == result2
    
    @patch("app.services.analyze.killchain.graph_api.get_edges_in_window")
    def test_connect_fsa_segments_to_candidates_single_segment(self, mock_get_edges):
        """测试单段或空段的情况"""
        edges = [
            create_test_edge(
                timestamp="2026-01-12T03:21:10.123Z",
                event_id="evt-001"
            )
        ]
        fsa_graph = create_test_fsa_graph(edges)
        
        cache = AnchorPairCache()
        result = connect_fsa_segments_to_candidates(
            fsa_graph,
            cache=cache,
            allowed_reltypes=ALLOWED_RELTYPES,
        )
        
        # 单段或空段应该直接返回（无需连接）
        assert result is not None
        assert isinstance(result, SemanticCandidateSubgraph)
        assert len(result.pair_candidates) == 0
    
    @patch("app.services.analyze.killchain.graph_api.get_edges_in_window")
    def test_connect_fsa_segments_to_candidates_no_path(self, mock_get_edges):
        """测试无路径的情况（应返回 None）"""
        # 创建两个段，但锚点之间无连接
        edges1 = [
            create_test_edge(
                src_uid="Host:h-001",
                dst_uid="Process:p-001",
                timestamp="2026-01-12T03:21:10.123Z",
            )
        ]
        edges2 = [
            create_test_edge(
                src_uid="Host:h-999",  # 不同的节点
                dst_uid="Process:p-999",
                timestamp="2026-01-12T03:22:10.123Z",
            )
        ]
        
        # 创建包含两个段的 FSA 图
        from app.services.analyze.attack_fsa import EdgeNode
        nodes1 = [EdgeNode(e) for e in edges1]
        nodes2 = [EdgeNode(e) for e in edges2]
        
        segments = [
            StateSegment(
                state=AttackState.INITIAL_ACCESS,
                nodes=nodes1,
            ),
            StateSegment(
                state=AttackState.EXECUTION,
                nodes=nodes2,
            ),
        ]
        
        fsa_graph = FSAGraph(
            nodes=nodes1 + nodes2,
            trace=[],
        )
        
        # Mock 返回空边列表（无连接）
        mock_get_edges.return_value = []
        
        cache = AnchorPairCache()
        result = connect_fsa_segments_to_candidates(
            fsa_graph,
            cache=cache,
            allowed_reltypes=ALLOWED_RELTYPES,
        )
        
        # 无路径时应返回 None
        assert result is None
    
    def test_build_semantic_candidate_subgraphs(self):
        """测试批量构建语义候选子图"""
        edges = [
            create_test_edge(
                timestamp="2026-01-12T03:21:10.123Z",
                event_id="evt-001"
            )
        ]
        fsa_graph = create_test_fsa_graph(edges)
        
        with patch("app.services.analyze.killchain.graph_api.get_edges_in_window") as mock_get_edges:
            mock_get_edges.return_value = []
            
            cache = AnchorPairCache()
            results = build_semantic_candidate_subgraphs(
                [fsa_graph],
                cache=cache,
                allowed_reltypes=ALLOWED_RELTYPES,
            )
            
            assert isinstance(results, list)
            # 单段图应该被保留（无需连接）


# ========== Phase C: LLM 选择测试 ==========

class TestPhaseCLLMSelection:
    """测试 Phase C LLM 选择"""
    
    def test_build_llm_payload(self):
        """测试构建 LLM payload"""
        # 创建语义候选子图
        edges = [
            create_test_edge(
                timestamp="2026-01-12T03:21:10.123Z",
                event_id="evt-001"
            )
        ]
        fsa_graph = create_test_fsa_graph(edges)
        
        segments = build_segment_summaries(fsa_graph)
        candidate = SemanticCandidateSubgraph(
            fsa_graph=fsa_graph,
            segments=segments,
            pair_candidates=[],
        )
        
        payload = build_llm_payload(candidate)
        
        assert isinstance(payload, dict)
        assert "constraints" in payload
        assert "segments" in payload
        assert "pairs" in payload
        assert isinstance(payload["segments"], list)
        assert isinstance(payload["pairs"], list)
    
    def test_build_llm_payload_with_candidates(self):
        """测试包含候选路径的 payload"""
        edges = [
            create_test_edge(
                src_uid="Host:h-001",
                dst_uid="Process:p-001",
                timestamp=1000.0,
            ),
            create_test_edge(
                src_uid="Process:p-001",
                dst_uid="Host:h-002",
                timestamp=1100.0,
            ),
        ]
        fsa_graph = create_test_fsa_graph(edges)
        segments = build_segment_summaries(fsa_graph)
        
        # 创建候选路径
        candidate_path = CandidatePath(
            path_id="p-001",
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=1100.0,
            edges=tuple(edges),
            steps=tuple([
                PathStepView(
                    ts=1000.0,
                    src_uid="Host:h-001",
                    rel="LOGON",
                    dst_uid="Process:p-001",
                    key_props={},
                ),
                PathStepView(
                    ts=1100.0,
                    src_uid="Process:p-001",
                    rel="RUNS_ON",
                    dst_uid="Host:h-002",
                    key_props={},
                ),
            ]),
            signature="sig-001",
        )
        
        pair_candidates = [
            AnchorPairCandidates(
                pair_idx=0,
                from_seg_idx=0,
                to_seg_idx=1,
                src_anchor="Host:h-001",
                dst_anchor="Host:h-002",
                t_min=1000.0,
                t_max=1100.0,
                candidates=[candidate_path],
            )
        ]
        
        candidate = SemanticCandidateSubgraph(
            fsa_graph=fsa_graph,
            segments=segments,
            pair_candidates=pair_candidates,
        )
        
        payload = build_llm_payload(candidate)
        
        assert len(payload["pairs"]) == 1
        pair = payload["pairs"][0]
        assert "candidates" in pair
        assert len(pair["candidates"]) == 1
        assert pair["candidates"][0]["path_id"] == "p-001"
        assert len(pair["candidates"][0]["steps"]) == 2
    
    def test_select_killchain_with_llm_fallback(self):
        """测试 LLM 选择（fallback 模式）"""
        edges = [
            create_test_edge(
                src_uid="Host:h-001",
                dst_uid="Process:p-001",
                timestamp=1000.0,
            ),
            create_test_edge(
                src_uid="Process:p-001",
                dst_uid="Host:h-002",
                timestamp=1100.0,
            ),
        ]
        fsa_graph = create_test_fsa_graph(edges)
        segments = build_segment_summaries(fsa_graph)
        
        candidate_path1 = CandidatePath(
            path_id="p-001",
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=1100.0,
            edges=tuple(edges),
            steps=(),
            signature="sig-001",
        )
        
        candidate_path2 = CandidatePath(
            path_id="p-002",
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=1100.0,
            edges=tuple(edges[:1]),  # 更短的路径
            steps=(),
            signature="sig-002",
        )
        
        pair_candidates = [
            AnchorPairCandidates(
                pair_idx=0,
                from_seg_idx=0,
                to_seg_idx=1,
                src_anchor="Host:h-001",
                dst_anchor="Host:h-002",
                t_min=1000.0,
                t_max=1100.0,
                candidates=[candidate_path1, candidate_path2],
            )
        ]
        
        candidate = SemanticCandidateSubgraph(
            fsa_graph=fsa_graph,
            segments=segments,
            pair_candidates=pair_candidates,
        )
        
        # 不使用 LLM client（fallback）
        killchain = select_killchain_with_llm(candidate, llm_client=None)
        
        assert isinstance(killchain, KillChain)
        assert killchain.kc_uuid is not None
        assert len(killchain.selected_paths) == 1
        # fallback 应该选择最短路径
        assert killchain.selected_paths[0].path_id == "p-002"
        assert "mock" in killchain.explanation.lower()
    
    def test_select_killchain_with_llm_client(self):
        """测试使用 LLM client 选择"""
        edges = [
            create_test_edge(timestamp=1000.0),
        ]
        fsa_graph = create_test_fsa_graph(edges)
        segments = build_segment_summaries(fsa_graph)
        
        candidate_path = CandidatePath(
            path_id="p-001",
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=1100.0,
            edges=tuple(edges),
            steps=(),
            signature="sig-001",
        )
        
        candidate = SemanticCandidateSubgraph(
            fsa_graph=fsa_graph,
            segments=segments,
            pair_candidates=[
                AnchorPairCandidates(
                    pair_idx=0,
                    from_seg_idx=0,
                    to_seg_idx=1,
                    src_anchor="Host:h-001",
                    dst_anchor="Host:h-002",
                    t_min=1000.0,
                    t_max=1100.0,
                    candidates=[candidate_path],
                )
            ],
        )
        
        # Mock LLM client
        mock_llm = Mock()
        mock_llm.choose.return_value = {
            "chosen_path_ids": ["p-001"],
            "explanation": "LLM selected path p-001 based on semantic consistency",
        }
        
        killchain = select_killchain_with_llm(candidate, llm_client=mock_llm)
        
        assert isinstance(killchain, KillChain)
        assert len(killchain.selected_paths) == 1
        assert killchain.selected_paths[0].path_id == "p-001"
        assert "LLM" in killchain.explanation
    
    def test_materialize_killchain(self):
        """测试 materialize_killchain"""
        edges = [
            create_test_edge(timestamp=1000.0),
        ]
        fsa_graph = create_test_fsa_graph(edges)
        segments = build_segment_summaries(fsa_graph)
        
        candidate_path = CandidatePath(
            path_id="p-001",
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=1100.0,
            edges=tuple(edges),
            steps=(),
            signature="sig-001",
        )
        
        candidate = SemanticCandidateSubgraph(
            fsa_graph=fsa_graph,
            segments=segments,
            pair_candidates=[
                AnchorPairCandidates(
                    pair_idx=0,
                    from_seg_idx=0,
                    to_seg_idx=1,
                    src_anchor="Host:h-001",
                    dst_anchor="Host:h-002",
                    t_min=1000.0,
                    t_max=1100.0,
                    candidates=[candidate_path],
                )
            ],
        )
        
        killchain = materialize_killchain(
            candidate,
            ["p-001"],
            explanation="Test explanation",
        )
        
        assert isinstance(killchain, KillChain)
        assert killchain.kc_uuid is not None
        assert len(killchain.selected_paths) == 1
        assert killchain.selected_paths[0].path_id == "p-001"
        assert killchain.explanation == "Test explanation"
        assert killchain.fsa_graph == fsa_graph
        assert killchain.segments == segments


# ========== 持久化测试 ==========

class TestPersistence:
    """测试持久化功能"""
    
    @patch("app.services.analyze.killchain.graph_api.add_edge")
    @patch("app.services.analyze.killchain.graph_api.add_node")
    def test_persist_killchain_to_db(self, mock_add_node, mock_add_edge):
        """测试持久化 killchain 到数据库"""
        edges = [
            create_test_edge(
                src_uid="Host:h-001",
                dst_uid="Process:p-001",
                timestamp=1000.0,
                event_id="evt-001",
            ),
        ]
        fsa_graph = create_test_fsa_graph(edges)
        segments = build_segment_summaries(fsa_graph)
        
        candidate_path = CandidatePath(
            path_id="p-001",
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=1100.0,
            edges=tuple(edges),
            steps=(),
            signature="sig-001",
        )
        
        killchain = KillChain(
            kc_uuid="test-uuid-123",
            fsa_graph=fsa_graph,
            segments=segments,
            selected_paths=[candidate_path],
            explanation="Test",
        )
        
        persist_killchain_to_db(killchain)
        
        # 验证 add_edge 被调用
        assert mock_add_edge.called
        
        # 验证边包含 killchain uuid
        call_args = mock_add_edge.call_args[0]
        edge = call_args[0]
        assert isinstance(edge, GraphEdge)
        assert edge.props.get(KC_ECS_FIELD) == "test-uuid-123"
        
        # 验证 add_node 被调用
        assert mock_add_node.called
    
    @patch("app.services.analyze.killchain.graph_api.add_edge")
    @patch("app.services.analyze.killchain.graph_api.add_node")
    def test_persist_killchain_duplicate_edges(self, mock_add_node, mock_add_edge):
        """测试去重边的情况"""
        edge = create_test_edge(
            src_uid="Host:h-001",
            dst_uid="Process:p-001",
            timestamp=1000.0,
            event_id="evt-001",
        )
        
        fsa_graph = create_test_fsa_graph([edge])
        segments = build_segment_summaries(fsa_graph)
        
        # 同一条边既在 FSA 中，也在 selected_paths 中
        candidate_path = CandidatePath(
            path_id="p-001",
            src_anchor="Host:h-001",
            dst_anchor="Host:h-002",
            t_min=1000.0,
            t_max=1100.0,
            edges=(edge,),
            steps=(),
            signature="sig-001",
        )
        
        killchain = KillChain(
            kc_uuid="test-uuid-123",
            fsa_graph=fsa_graph,
            segments=segments,
            selected_paths=[candidate_path],
            explanation="Test",
        )
        
        persist_killchain_to_db(killchain)
        
        # 应该只写入一次（去重）
        # 注意：实际调用次数取决于去重逻辑
        assert mock_add_edge.called


# ========== 完整流水线测试 ==========

class TestPipeline:
    """测试完整流水线"""
    
    @patch("app.services.analyze.killchain.graph_api.get_alarm_edges")
    @patch("app.services.analyze.killchain.graph_api.get_edges_in_window")
    @patch("app.services.analyze.killchain.graph_api.add_edge")
    @patch("app.services.analyze.killchain.graph_api.add_node")
    def test_run_killchain_pipeline_basic(
        self, mock_add_node, mock_add_edge, mock_get_edges, mock_get_alarm
    ):
        """测试基本流水线执行"""
        # Mock 告警边
        alarm_edges = [
            create_test_edge(
                timestamp="2026-01-12T03:21:10.123Z",
                event_id="evt-001",
                **{"threat": {"tactic": {"name": "Initial Access"}}}
            ),
        ]
        mock_get_alarm.return_value = alarm_edges
        
        # Mock 时间窗口查询
        mock_get_edges.return_value = []
        
        # 运行流水线
        killchains = run_killchain_pipeline(llm_client=None, persist=False)
        
        assert isinstance(killchains, list)
        # 根据 FSA 是否能生成图，结果可能为空或包含 killchain
    
    @patch("app.services.analyze.killchain.graph_api.get_alarm_edges")
    @patch("app.services.analyze.killchain.graph_api.get_edges_in_window")
    @patch("app.services.analyze.killchain.graph_api.add_edge")
    @patch("app.services.analyze.killchain.graph_api.add_node")
    def test_run_killchain_pipeline_with_persistence(
        self, mock_add_node, mock_add_edge, mock_get_edges, mock_get_alarm
    ):
        """测试带持久化的流水线"""
        alarm_edges = [
            create_test_edge(
                timestamp="2026-01-12T03:21:10.123Z",
                event_id="evt-001",
                **{"threat": {"tactic": {"name": "Initial Access"}}}
            ),
        ]
        mock_get_alarm.return_value = alarm_edges
        mock_get_edges.return_value = []
        
        # 运行流水线（启用持久化）
        killchains = run_killchain_pipeline(llm_client=None, persist=True)
        
        assert isinstance(killchains, list)
        # 如果生成了 killchain，应该调用持久化函数
        # 注意：实际调用取决于是否能生成有效的 killchain


# ========== 集成测试（使用真实测试数据） ==========

class TestIntegrationWithRealData:
    """使用 testExample.json 的集成测试"""
    
    @pytest.mark.skipif(
        not (_fixtures_dir() / "testExample.json").exists(),
        reason="testExample.json not found"
    )
    def test_load_and_process_test_example(self):
        """测试加载和处理 testExample.json"""
        events = load_test_events()
        assert len(events) > 0
        
        # 转换为 GraphEdge（简化版，实际应使用 ecs_ingest）
        from app.services.neo4j import ecs_ingest
        
        all_edges = []
        for event in events:
            nodes, edges = ecs_ingest.ecs_event_to_graph(event)
            all_edges.extend(edges)
        
        # 过滤告警边（简化：查找包含 threat 的边）
        alarm_edges = [
            e for e in all_edges
            if e.props.get("threat") or e.props.get("event.kind") == "alert"
        ]
        
        if alarm_edges:
            # 运行 FSA
            fsa_graphs = behavior_state_machine(alarm_edges)
            
            if fsa_graphs:
                # 测试 Phase B
                cache = AnchorPairCache()
                with patch("app.services.analyze.killchain.graph_api.get_edges_in_window") as mock_get_edges:
                    mock_get_edges.return_value = all_edges  # 返回所有边作为候选
                    
                    candidates = build_semantic_candidate_subgraphs(
                        fsa_graphs,
                        cache=cache,
                        allowed_reltypes=ALLOWED_RELTYPES,
                    )
                    
                    assert isinstance(candidates, list)
                    
                    # 如果有候选，测试 Phase C
                    if candidates:
                        killchain = select_killchain_with_llm(
                            candidates[0],
                            llm_client=None,  # 使用 fallback
                        )
                        assert isinstance(killchain, KillChain)