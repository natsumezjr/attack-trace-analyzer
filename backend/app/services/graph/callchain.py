from __future__ import annotations

import math  
from collections import defaultdict 
from dataclasses import dataclass, field
from typing import Any, List, Sequence, Tuple, Dict, Optional, Set

from api import get_alarm_edges
from models import GraphEdge, RelType
from utils import _parse_ts_to_float
from ..data.attack_fsa import FSAGraph, KillChainEdgeNode


# ==========================================
# 1. 基础配置 (Configuration)
# ==========================================

# 基础威胁权重表
BASE_RISK_WEIGHTS: Dict[str, float] = {
    RelType.SPAWNED.value: 5.0,     # 进程衍生
    RelType.CONNECTED.value: 4.0,   # C2通信
    RelType.LOGON.value: 3.0,       # 横向移动
    RelType.ACCESSED.value: 2.0,    # 文件读写
    RelType.RESOLVES_TO.value: 1.0, # 基础设施
    RelType.RESOLVED.value: 1.0,
}

# 向量特征库 (Knowledge Base) - 模拟数据
# 实际应从 Milvus/OpenSearch 加载
VECTOR_DB_SIGNATURES = {
    "Ransomware":       [0.9, 0.9, 0.8, 0.1, 0.1, 0.1, 0.9, 0.8],
    "CryptoMiner":      [0.2, 0.1, 0.9, 0.9, 0.1, 0.1, 0.1, 0.2],
    "DataExfiltration": [0.1, 0.2, 0.1, 0.9, 0.9, 0.9, 0.2, 0.1],
    "APT_Lateral":      [0.8, 0.1, 0.1, 0.1, 0.8, 0.1, 0.1, 0.9],
}

# ==========================================
# 2. 中间数据结构 (Structures)
# ==========================================

@dataclass
class Subgraph:
    """
    处理用的中间图结构，用于存储从 FSA 转换而来并补全后的图。
    """
    nodes: dict[str, Any] = field(default_factory=dict) # 存储节点信息
    edges: list[GraphEdge] = field(default_factory=list)
    
    # 邻接表索引：key=dst_uid, value=list[incoming_edges]
    # 用于从结果向原因倒推 (Backtracking)
    _incoming_index: dict[str, list[GraphEdge]] = field(default_factory=lambda: defaultdict(list))

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        self._incoming_index[edge.dst_uid].append(edge)
        # 这里为了简化，假设节点信息已经在上下文中，实际项目中可能需要 fetch_node

    def get_incoming_edges(self, node_uid: str) -> list[GraphEdge]:
        return self._incoming_index[node_uid]

@dataclass
class CallChain:
    """最终输出的攻击链结果"""
    chain: List[GraphEdge] = field(default_factory=list)
    score: float = 0.0
    
    @property
    def length(self) -> int:
        return len(self.chain)

# ==========================================
# 3. 模拟组件 (Mock Components)
# ==========================================

class MockLLMClient:
    """模拟 LLM 用于语义分析和报告生成"""
    @staticmethod
    def analyze_intent(src_uid: str, action: str, dst_uid: str) -> Tuple[float, List[float]]:
        # 模拟：生成 8 维向量
        # 实际逻辑：调用 Embedding API
        confidence = 0.1
        
        # 简单的模拟逻辑：如果是 Powershell 相关的行为，置信度高
        if "powershell" in str(src_uid).lower() or "cmd" in str(src_uid).lower():
            confidence = 0.9
        
        vector = [0.1 * confidence] * 8 
        # 对 vector 进行微扰动以模拟多样性
        if action == "CONNECTED": vector[3] = 0.9 
        
        return confidence, vector

    @staticmethod
    def generate_report(chain_details: str, match_result: dict) -> str:
        return (f"【SECURITY REPORT】\n"
                f"Detected Threat: {match_result['attack_type']} (Similarity: {match_result['confidence']})\n"
                f"Attack Chain Narrative:\n{chain_details}\n"
                f"AI Suggestion: Isolate involved hosts and reset credentials.")

# ==========================================
# 4. Phase B: 图补全与连通性验证 (Graph Completion & Validation)
# ==========================================

def check_graph_connectivity(subgraph: Subgraph) -> bool:
    """
    检查子图是否弱连通 (Weakly Connected)。
    即：忽略边的方向，任意两个节点之间是否存在路径。
    """
    if not subgraph.edges:
        return False
        
    # 构建无向邻接表
    adjacency = defaultdict(set)
    all_nodes = set()
    
    for edge in subgraph.edges:
        u, v = edge.src_uid, edge.dst_uid
        adjacency[u].add(v)
        adjacency[v].add(u)
        all_nodes.add(u)
        all_nodes.add(v)
        
    if not all_nodes:
        return False

    # BFS 遍历
    start_node = next(iter(all_nodes))
    visited = {start_node}
    queue = [start_node]
    
    while queue:
        curr = queue.pop(0)
        for neighbor in adjacency[curr]:
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
                
    # 如果访问到的节点数等于总节点数，说明连通
    return len(visited) == len(all_nodes)

def connect_fsa_segments(fsa_graph: FSAGraph) -> Optional[Subgraph]:
    """
    Phase B 新逻辑：
    1. 获取分段 (Segments)。
    2. 尝试在相邻分段的锚点之间寻找数据库中存在的直接边。
    3. 如果所有分段都能连接上，且最终图连通，则返回 Subgraph；否则返回 None。
    注意：此过程只增加边，不增加新节点。
    """
    segs = fsa_graph.segments()
    processing_sg = Subgraph()

    # 1. 基础情况：无论如何，先把 FSA 原始识别出的边加入子图
    for node in fsa_graph.nodes:
        processing_sg.add_edge(node.edge)

    # 只有一个段或没有段，只需检查自身连通性（通常一个段内是连通的，但为了保险）
    if len(segs) <= 1:
        if check_graph_connectivity(processing_sg):
            return processing_sg
        return None

    # 2. 段间连接 (Segment Stitching)
    for i in range(len(segs) - 1):
        seg_curr = segs[i]
        seg_next = segs[i+1]

        # 获取锚点
        src_anchor = seg_curr.anchor_out_uid
        dst_anchor = seg_next.anchor_in_uid
        
        # 获取时间窗口 (前一段结束 -> 后一段开始)
        # 允许微小的误差窗口 (e.g., +/- 1s)
        t_min = seg_curr.t_end
        t_max = seg_next.t_start
        
        # 异常情况：时间倒流，放弃
        if t_min > t_max:
            # 除非是允许并发的时间窗口，否则视为无效序列
            return None

        # 3. 数据库查询：寻找两个锚点之间的直接连边
        # 限制：只能找 src_anchor -> dst_anchor 的直接边，不引入第三方节点
        # 模拟 API 调用：get_edges_between_specific_nodes(src, dst, t_start, t_end)
        
        # 这里我们需要实现一个特定的查询，只查这两个点
        bridge_edges = get_edges_inter_nodes(
            node_uids=[src_anchor, dst_anchor], 
            t_start=t_min - 1.0, # 稍微放宽一点
            t_end=t_max + 1.0
        )
        
        # 过滤：确保边的方向和两端严格匹配锚点
        valid_bridges = []
        for edge in bridge_edges:
            # 必须是 src -> dst，或者是双向交互
            if edge.src_uid == src_anchor and edge.dst_uid == dst_anchor:
                valid_bridges.append(edge)
        
        # 约束：如果在两个段之间找不到任何连接边，则该分布子图无法连通，丢弃
        if not valid_bridges:
            return None # Drop this graph completely
            
        # 将找到的桥接边加入子图
        for edge in valid_bridges:
            edge.props['is_context'] = True # 标记为补全边
            processing_sg.add_edge(edge)

    # 4. 最终连通性检查
    # 虽然我们要么是一个段，要么段之间都补上了边，但为了严谨（防止内部断裂），做一次全局检查
    if check_graph_connectivity(processing_sg):
        return processing_sg
    
    return None

# ==========================================
# 5. Phase C: 语义赋权与向量化 (Enrichment)
# ==========================================

def enrich_edges_with_semantics(subgraph: Subgraph) -> None:
    """
    遍历子图中的所有边：
    1. 计算权重 = 基础分 * (1 + LLM置信度)
    2. 生成向量并挂载到 edge.props['vector']
    """
    for edge in subgraph.edges:
        # 1. 获取基础权重
        base_score = BASE_RISK_WEIGHTS.get(edge.rtype.value, 1.0)
        
        # 2. LLM 分析 (强特征)
        # 真实场景需传入详细 Context (如命令行、Payload)
        llm_conf, vector = MockLLMClient.analyze_intent(edge.src_uid, edge.rtype.value, edge.dst_uid)
        
        # 3. 动态计算最终权重
        # 如果 LLM 认为恶意 (0.9)，权重直接翻倍；如果认为正常 (0.1)，权重基本不变
        final_weight = base_score * (1.0 + llm_conf)
        
        # 4. 存储 (边算边存)
        edge.props['weight'] = final_weight
        edge.props['vector'] = vector
        edge.props['llm_confidence'] = llm_conf

# ==========================================
# 6. Phase D: 回溯分析 (Backtracking / DP)
# ==========================================

def backtrack_max_risk_chain(subgraph: Subgraph) -> CallChain:
    """
    在完全连通子图中，寻找总权重最高的攻击路径。
    使用动态规划 (DP)。
    """
    if not subgraph.edges:
        return CallChain()

    # 按时间排序，确保因果顺序
    sorted_edges = sorted(
        [e for e in subgraph.edges if e.get_ts()], 
        key=lambda x: _parse_ts_to_float(x.get_ts())
    )
    
    if not sorted_edges:
        return CallChain()

    # Memo: edge_id -> (cumulative_score, path_list)
    memo: Dict[str, Tuple[float, List[GraphEdge]]] = {}

    def get_max_path_to(curr_edge: GraphEdge) -> Tuple[float, List[GraphEdge]]:
        e_id = f"{curr_edge.src_uid}->{curr_edge.dst_uid}:{curr_edge.get_ts()}"
        if e_id in memo: return memo[e_id]

        # 当前边的权重 (已经在 Phase C 算好存进去了)
        w = curr_edge.props.get('weight', 1.0)
        curr_ts = _parse_ts_to_float(curr_edge.get_ts())

        max_prev_score = 0.0
        best_prev_path = []

        # 查找所有入边 (前驱)
        incoming_candidates = subgraph.get_incoming_edges(curr_edge.src_uid)

        for prev in incoming_candidates:
            prev_ts = _parse_ts_to_float(prev.get_ts())
            
            # [硬规则] 时序单调性约束
            if prev_ts > curr_ts + 1.0: continue # 允许1秒误差
            
            # [剪枝] 时间跨度过大 (例如超过30天) 视为无因果关联
            if curr_ts - prev_ts > 86400 * 30: continue

            p_score, p_path = get_max_path_to(prev)
            
            if p_score > max_prev_score:
                max_prev_score = p_score
                best_prev_path = p_path
        
        total = max_prev_score + w
        full_path = best_prev_path + [curr_edge]
        
        memo[e_id] = (total, full_path)
        return total, full_path

    # [策略] 寻找全局最优解
    # 遍历所有边作为“终点”的可能性，取 Score 最高的一条
    global_max_score = 0.0
    global_best_chain = []

    for edge in sorted_edges:
        score, chain = get_max_path_to(edge)
        if score > global_max_score:
            global_max_score = score
            global_best_chain = chain
            
    return CallChain(chain=global_best_chain, score=global_max_score)

# ==========================================
# 7. Phase E & F: 匹配与报告
# ==========================================

def extract_vectors_from_chain(chain: CallChain) -> List[List[float]]:
    """从回溯好的链中直接提取已存储的向量"""
    vectors = []
    for edge in chain.chain:
        v = edge.props.get('vector')
        if v:
            vectors.append(v)
        else:
            vectors.append([0.0] * 8)
    return vectors

def match_vector_features(vectors: List[List[float]]) -> Dict[str, Any]:
    """特征库比对 (余弦相似度)"""
    if not vectors:
        return {"attack_type": "Unknown", "confidence": 0.0}

    # 计算质心 (Centroid)
    dim = len(vectors[0])
    avg_vec = [0.0] * dim
    for v in vectors:
        for i in range(dim):
            avg_vec[i] += v[i]
    avg_vec = [x / len(vectors) for x in avg_vec]

    # 数学辅助：余弦相似度
    def cosine_sim(v1, v2):
        dot = sum(a*b for a,b in zip(v1, v2))
        mag1 = math.sqrt(sum(a*a for a in v1))
        mag2 = math.sqrt(sum(b*b for b in v2))
        return dot / (mag1 * mag2) if mag1 and mag2 else 0.0

    best_type = "Unknown"
    max_sim = -1.0
    
    for name, sig in VECTOR_DB_SIGNATURES.items():
        if len(sig) != dim: continue
        sim = cosine_sim(avg_vec, sig)
        if sim > max_sim:
            max_sim = sim
            best_type = name
            
    return {"attack_type": best_type, "confidence": round(max_sim, 4)}

# ==========================================
# 8. 主编排 (Main Pipeline)
# ==========================================

def run_killchain_pipeline_final() -> None:
    print("[*] Starting Kill Chain Analysis Pipeline (Segment-Based)...")
    
    from ..data.attack_fsa import behavior_state_machine
    
    # 1. Phase A: 获取数据并生成 FSA Graphs
    abnormal_edges = get_alarm_edges()
    fsa_graphs = behavior_state_machine(abnormal_edges)
    print(f"[*] Phase A: Generated {len(fsa_graphs)} potential distributed subgraphs.")

    valid_subgraphs = []

    # 2. Phase B: 基于分段的连接与补全
    for i, fsa_graph in enumerate(fsa_graphs):
        # 使用新的逻辑尝试连接分段
        subgraph = connect_fsa_segments(fsa_graph)
        
        if subgraph:
            print(f"  > Graph #{i} connected successfully ({len(subgraph.edges)} edges).")
            valid_subgraphs.append(subgraph)
        else:
            print(f"  > Graph #{i} discarded (disconnected segments).")

    # 后续流程仅针对有效连通的子图进行
    for i, subgraph in enumerate(valid_subgraphs):
        print(f"\n--- Analyzing Valid Subgraph #{i} ---")

        # 3. Phase C: 语义赋权 (Enrichment)
        enrich_edges_with_semantics(subgraph)
        
        # 4. Phase D: 溯源回溯 (Backtracking)
        call_chain = backtrack_max_risk_chain(subgraph)
        
        if call_chain.length == 0:
            print("[!] No valid chain found after backtracking.")
            continue
            
        print(f"[*] Phase D: Found Chain (Length: {call_chain.length}, Score: {call_chain.score:.2f})")

        # 5. Phase E: 向量匹配
        chain_vectors = extract_vectors_from_chain(call_chain)
        match_result = match_vector_features(chain_vectors)
        
        # 6. Phase F: 报告
        chain_text = "\n".join(
            f"[{e.get_ts()}] {e.src_uid} --{e.rtype.value}--> {e.dst_uid} (W:{e.props['weight']:.1f})"
            for e in call_chain.chain
        )
        report = MockLLMClient.generate_report(chain_text, match_result)
        print(report)

if __name__ == "__main__":
    # 为了让代码片段在单文件中运行，补充必要的 Mock 辅助函数
    # 实际运行时请移除这些 mock，使用 import
    def _parse_ts_to_float(ts_str):
        # 简单模拟：假设 ts_str 是 float 字符串或者 int
        try:
            return float(ts_str)
        except:
            return 0.0
            
    # 给 GraphEdge 增加辅助方法 (Monkey Patching for demo)
    GraphEdge.get_ts_float = lambda self: _parse_ts_to_float(self.get_ts())

    run_killchain_pipeline_final()