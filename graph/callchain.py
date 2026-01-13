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

# 模拟 LLM 客户端
class MockLLMClient:
    """
    实际项目中请替换为真实的 LangChain 或 OpenAI 客户端
    """
    @staticmethod
    def analyze_intent(src_context: dict, action: str, dst_context: dict) -> tuple[float, list[float]]:
        # 返回: (恶意置信度 0.0-1.0, 行为特征向量 128维)
        # 这是一个模拟逻辑：如果进程名包含 weird 字符或者是 powershell，认为高危
        proc_name = src_context.get('process.name', '')
        cmd_line = src_context.get('process.command_line', '')
        
        risk_score = 0.1
        if "powershell" in proc_name or "cmd.exe" in proc_name:
            risk_score = 0.8
        if "encoded" in cmd_line or "-nop" in cmd_line:
            risk_score = 0.95
            
        # 模拟返回一个随机向量
        mock_vector = [0.1 * risk_score] * 8  # 简化为8维演示
        return risk_score, mock_vector

# 时间解析工具
from datetime import datetime

# 时间解析工具
def _parse_ts_to_float(ts: str | None) -> float:
    """
    将 UTC 时间字符串 (ISO 8601) 或 数字字符串 转换为 Unix 时间戳 (float)
    例如: "2023-10-27T10:00:00Z" -> 1698400800.0
    """
    if not ts:
        return 0.0
    # 1. 尝试直接转换为 float (兼容数据库里存的已经是秒数的情况)
    try:
        return float(ts)
    except ValueError:
        pass

    # 2. 解析 ISO 8601 格式字符串
    try:
        # 处理 'Z' 后缀：Python 3.11 以前的 fromisoformat 不支持 'Z' 结尾，
        # 需要将其替换为 '+00:00' 来表示 UTC 时区。
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
            
        # 解析字符串为 datetime 对象
        dt = datetime.fromisoformat(ts)
        
        # 转换为 Unix 时间戳 (float 秒数)
        return dt.timestamp()
        
    except (ValueError, TypeError):
        # 如果格式依然无法解析，返回 0.0 作为兜底，防止程序崩溃
        return 0.0

# 核心溯源逻辑
def _calculate_edge_weight_and_vector(
    edge: GraphEdge, 
    subgraph: Subgraph
) -> Tuple[float, list[float]]:
    """
    计算单条边的威胁权重，并提取向量。
    Logic: BaseWeight + (LLM_Confidence * Alpha)
    """
    # 1. 基础权重
    base_score = BASE_RISK_WEIGHTS.get(edge.rtype, 1.0)
    
    # 2. 准备上下文给 LLM
    src_node = subgraph.get_node(edge.src_uid)
    dst_node = subgraph.get_node(edge.dst_uid)
    
    src_ctx = src_node.merged_props() if src_node else {}
    dst_ctx = dst_node.merged_props() if dst_node else {}
    
    # 3. LLM 语义分析 (Semantic Analysis)
    # 优化点：并非每条边都调 LLM，可以加一个白名单过滤
    llm_confidence, vector = MockLLMClient.analyze_intent(
        src_context=src_ctx,
        action=edge.rtype.value,
        dst_context=dst_ctx
    )
    
    # 4. 融合打分公式
    # 权重 = 基础分 * (1 + LLM置信度)
    # 例如：Powershell(5.0) 被 LLM 判定为恶意(0.9) -> 5.0 * 1.9 = 9.5 分
    final_weight = base_score * (1.0 + llm_confidence)
    
    return final_weight, vector


def backtrack_call_chain(subgraph: Subgraph, alarm_edge: GraphEdge | None = None) -> CallChain:
    """
    核心回溯函数：寻找从根源到告警点的最大风险路径 (Critical Path Analysis)
    """
    # 0. 边界检查
    if not subgraph.edges:
        return CallChain()
    
    # 如果没指定告警边，按时间找最后一条高危边
    if alarm_edge is None:
        # 简单策略：找时间最近的一条边
        valid_edges = [e for e in subgraph.edges if e.get_ts()]
        if not valid_edges:
            return CallChain()
        # 按时间排序
        valid_edges.sort(key=lambda e: _parse_ts_to_float(e.get_ts()))
        alarm_edge = valid_edges[-1]

    print(f"[*] Starting backtrack analysis from Alert: {alarm_edge.rtype} ({alarm_edge.src_uid} -> {alarm_edge.dst_uid})")

    # ==========================================
    # 动态规划 (Dynamic Programming) 状态容器
    # memo[edge_id] = (accumulated_score, path_list_of_edges)
    # ==========================================
    memo: dict[str, Tuple[float, list[GraphEdge]]] = {}
    
    # 为了避免环路（虽然理论上时间单调不会有环，但以防万一），记录递归栈
    recursion_stack: set[str] = set()

    def get_max_risk_path_to(current_edge: GraphEdge) -> Tuple[float, list[GraphEdge]]:
        """
        递归函数：返回以 current_edge 为【终点】的最高分路径
        """
        edge_id = f"{current_edge.src_uid}->{current_edge.dst_uid}:{current_edge.get_ts()}"
        
        # 1. 查缓存 (Memoization)
        if edge_id in memo:
            return memo[edge_id]
        
        if edge_id in recursion_stack:
            # 检测到环，直接中断该分支
            return 0.0, []
        
        recursion_stack.add(edge_id)

        # 2. 计算当前边的权重与向量
        # 注意：这里我们立即做向量化，实现了“边存储+向量化”
        w, vec = _calculate_edge_weight_and_vector(current_edge, subgraph)
        
        # 将向量和权重写回属性，供后续步骤使用
        current_edge.props['weight'] = w
        current_edge.props['vector'] = vec  # 向量化存储

        curr_ts = _parse_ts_to_float(current_edge.get_ts())

        # 3. 寻找前驱 (Predecessors)
        # 逻辑：查找所有 指向 current_edge.src 的边
        incoming_candidates = subgraph.get_incoming_edges(current_edge.src_uid)
        
        max_prev_score = 0.0
        best_prev_path = []

        for prev_edge in incoming_candidates:
            prev_ts = _parse_ts_to_float(prev_edge.get_ts())
            
            # --- 规则1：时序单调性约束 (Time Monotonicity) ---
            # 允许 0.1秒 的时钟偏差 (skew tolerance)
            if prev_ts > curr_ts + 0.1: 
                continue

            # --- 规则2：剪枝逻辑 (Pruning) ---
            # 比如：如果 prev 是 LOGON 但时间在 30天前，太久远，剪掉
            if curr_ts - prev_ts > 86400 * 30: # 30 days
                continue

            # 递归求解
            prev_score, prev_path = get_max_risk_path_to(prev_edge)
            
            # 更新最大路径
            if prev_score > max_prev_score:
                max_prev_score = prev_score
                best_prev_path = prev_path

        # 4. 聚合结果
        # 当前路径 = 最优前驱路径 + 当前边
        total_score = max_prev_score + w
        current_full_path = best_prev_path + [current_edge]
        
        # 存入缓存
        memo[edge_id] = (total_score, current_full_path)
        recursion_stack.remove(edge_id)
        
        return total_score, current_full_path


    # 执行分析    
    # 启动 DP 搜索
    final_score, best_chain_list = get_max_risk_path_to(alarm_edge)
    
    print(f"[*] Backtrack complete. Chain Length: {len(best_chain_list)}, Risk Score: {final_score:.2f}")

    # 封装结果
    return CallChain(chain=best_chain_list)
    
    
#### 5. 向量提取
def extract_vectors(chain: CallChain) -> list[list[float]]:
    vectors = []
    for edge in chain.chain:
        # 模拟：将 Edge 的属性 (rtype, props) 转化为向量
        v = [1.0, 0.5] 
        vectors.append(v)
    return vectors

#### 6.特征匹配
def match_vector_features(vectors: list[list[float]]) -> dict[str, Any]:
    return {"attack_type": "Ransomware", "confidence": 0.98}

#### 7. LLM 分析
def analyze_with_llm(match_result: dict[str, Any], chain: CallChain) -> str:
    # 构建 Prompt，描述 chain 里的每一步
    chain_desc = "\n".join(
        f"{e.get_ts()}: {e.src_uid} --[{e.rtype}]--> {e.dst_uid}" 
        for e in chain.chain
    )
    return f"Analysis: Detected {match_result['attack_type']}.\nDetails:\n{chain_desc}"


# ==========================================
# 编排入口 (Orchestrator)
# ==========================================

def run_analysis_pipeline() -> None:
    print("[*] Starting Pipeline...")
    
    # 1. Get Data
    normal, abnormal = fetch_edges_from_db()
    
    # 2. State Machine -> Subgraphs
    subgraphs = behavior_state_machine(normal, abnormal)
    
    for i, sg in enumerate(subgraphs):
        # 3. Expand Context
        complete_sg = expand_to_complete_subgraph(sg)
        
        # 4. Backtrack (Pure Logic)
        call_chain = backtrack_call_chain(complete_sg)
        
        if call_chain.length == 0:
            continue
            
        # 5. Vectors
        vectors = extract_vectors(call_chain)
        
        # 6. Match
        match_res = match_vector_features(vectors)
        
        # 7. LLM
        report = analyze_with_llm(match_res, call_chain)
        
        print(f"--- Alert #{i} ---")
        print(report)

if __name__ == "__main__":
    run_analysis_pipeline()