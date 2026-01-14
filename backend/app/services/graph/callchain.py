from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, List, Sequence, Tuple, Dict, Optional, Set

from .api import get_alarm_edges, get_edges_inter_nodes,get_node
from .models import GraphEdge, RelType,NodeType,parse_uid
from .utils import _parse_ts_to_float
from ..algorithm.attack_fsa import FSAGraph


# ==========================================
# 1. 上下文管理 (Context Hydration)
# ==========================================

@dataclass
class EntityContext:
    """实体的详细上下文信息"""
    uid: str
    entity_type: str  # e.g., "Process", "File"
    name: str         # e.g., "powershell.exe", "192.168.1.5"
    description: str  # LLM 可读的自然语言描述


class ContextManager:
    """
    负责将抽象的 UID (如 'Process:p-1234abcd...') 转换为 LLM 可读的详细信息。
    """

    def __init__(self):
        # 简单的内存缓存: {uid: EntityContext}
        self._cache: Dict[str, EntityContext] = {}

    def hydrate(self, uid: str) -> EntityContext:
        """
        获取节点的详细上下文。
        优先查缓存，缓存未命中则查询 Neo4j 数据库。
        """
        if uid in self._cache:
            return self._cache[uid]

        # 调用 API 查询数据库
        graph_node = get_node(uid)

        # 1. 如果数据库里没有查到，尝试从 UID 解析基础信息
        if not graph_node:
            try:
                ntype, key_dict = parse_uid(uid)
                # 尝试从 key 中恢复一些信息作为兜底
                fallback_name = self._extract_name_from_key(ntype, key_dict)
                unknown_ctx = EntityContext(
                    uid=uid,
                    entity_type=ntype.value,
                    name=fallback_name,
                    description=f"Unknown {ntype.value} (ID: {uid}) - Details missing in DB."
                )
                self._cache[uid] = unknown_ctx
                return unknown_ctx
            except ValueError:
                # 连 UID 格式都不对的情况
                error_ctx = EntityContext(uid, "Unknown", uid, f"Invalid Entity ID: {uid}")
                self._cache[uid] = error_ctx
                return error_ctx

        # 2. 合并 Key 和 Props
        # GraphNode 的 key 和 props 是分开存的，合并以便统一处理
        full_props = graph_node.merged_props()
        
        # 3. 提取信息
        ntype_str = graph_node.ntype.value
        name = self._extract_name(graph_node.ntype, full_props)
        description = self._build_natural_language_desc(graph_node.ntype, name, full_props)

        context = EntityContext(
            uid=uid,
            entity_type=ntype_str,
            name=name,
            description=description
        )

        self._cache[uid] = context
        return context

    def _extract_name_from_key(self, ntype: NodeType, key: Dict[str, Any]) -> str:
        """从解析出的 UID Key 中尝试提取名字（兜底用）"""
        if ntype == NodeType.HOST:
            return key.get("host.id", "unknown_host")
        if ntype == NodeType.USER:
            return key.get("user.name") or key.get("user.id") or "unknown_user"
        if ntype == NodeType.PROCESS:
            # Process 的 key 只有 entity_id，看不出名字，只能返回 ID
            return key.get("process.entity_id", "unknown_process")
        if ntype == NodeType.FILE:
            # key 可能是 file.path
            return key.get("file.path", "unknown_file")
        if ntype == NodeType.IP:
            return key.get("ip", "unknown_ip")
        if ntype == NodeType.DOMAIN:
            return key.get("domain.name", "unknown_domain")
        return "unknown_entity"

    def _extract_name(self, ntype: NodeType, props: Dict[str, Any]) -> str:
        """
        根据节点类型提取最适合人类阅读的主名称。
        依据 models.py 中的字段定义。
        """
        if ntype == NodeType.PROCESS:
            # 优先: executable > name > command_line > entity_id
            return (props.get("process.executable") or 
                    props.get("process.name") or 
                    props.get("process.command_line") or 
                    props.get("process.entity_id", "Unknown Process"))
        
        elif ntype == NodeType.FILE:
            # 优先: file.path (models里定义的key) > file.name
            return props.get("file.path") or props.get("file.name") or "Unknown File"
        
        elif ntype == NodeType.USER:
            # 优先: user.name > user.id
            return props.get("user.name") or props.get("user.id") or "Unknown User"
        
        elif ntype == NodeType.IP:
            return props.get("ip", "Unknown IP")
        
        elif ntype == NodeType.DOMAIN:
            return props.get("domain.name", "Unknown Domain")
        
        elif ntype == NodeType.HOST:
            return props.get("host.name") or props.get("host.id") or "Unknown Host"
        
        return props.get("name", "Unknown Entity")

    def _build_natural_language_desc(self, ntype: NodeType, name: str, props: Dict[str, Any]) -> str:
        """
        构建 Prompt 描述。
        严格对应 models.py 中定义的字段。
        """
        parts = [f"Type: {ntype.value}", f"Name: '{name}'"]

        if ntype == NodeType.PROCESS:
            # 核心字段: command_line, pid, executable, start, host.id
            if cmd := props.get("process.command_line"):
                parts.append(f"Cmd: `{cmd}`")
            if pid := props.get("process.pid"):
                parts.append(f"PID: {pid}")
            if exe := props.get("process.executable"):
                # 如果名字已经展示了 exe，这里就不重复了，除非不一样
                if exe != name:
                    parts.append(f"Exe: {exe}")
            if user := props.get("user.name"): # 有时进程会附带用户信息
                parts.append(f"User: {user}")
            if parent_exe := props.get("process.parent.executable"): # 常见的 ECS 扩展字段
                parts.append(f"Parent: {parent_exe}")

        elif ntype == NodeType.FILE:
            # 核心字段: path, hash, host.id
            if path := props.get("file.path"):
                if path != name:
                    parts.append(f"Path: {path}")
            
            # Hash 处理
            hashes = []
            if sha256 := props.get("file.hash.sha256"): hashes.append(f"SHA256:{sha256}")
            if sha1 := props.get("file.hash.sha1"): hashes.append(f"SHA1:{sha1}")
            if md5 := props.get("file.hash.md5"): hashes.append(f"MD5:{md5}")
            
            if hashes:
                parts.append(f"Hashes: [{', '.join(hashes)}]")

        elif ntype == NodeType.USER:
            # 核心字段: user.id, user.name, host.id, domain
            if uid := props.get("user.id"):
                parts.append(f"ID: {uid}")
            if domain := props.get("user.domain"):
                parts.append(f"Domain: {domain}")
            # 如果是 User 节点，通常关联了 Host
            if host_id := props.get("host.id"):
                parts.append(f"HostID: {host_id}")

        elif ntype == NodeType.IP:
            # 核心字段: ip, geo, asn
            # 注意: models.py 只定义了 ip 字段，其他字段通常在 props 里
            if loc := props.get("geo.location"): # 假设 ECS 字段
                parts.append(f"Geo: {loc}")
            if asn := props.get("as.organization.name"): # 假设 ECS 字段
                parts.append(f"ASN: {asn}")

        elif ntype == NodeType.HOST:
            # 核心字段: host.id, host.name, os
            if hid := props.get("host.id"):
                parts.append(f"ID: {hid}")
            if os_name := props.get("host.os.name"): # 假设 ECS 字段
                parts.append(f"OS: {os_name}")

        elif ntype == NodeType.DOMAIN:
            # 核心字段: domain.name
            pass

        # 通用兜底：如果有关联的威胁标签
        if threat := props.get("threat.tactic.name"):
            parts.append(f"[THREAT TACTIC: {threat}]")
        if risk := props.get("risk_score"):
            parts.append(f"[RISK SCORE: {risk}]")

        return " | ".join(parts)

# ==========================================
# 2. 数据结构 (保留 Subgraph, 新增 Result)
# ==========================================

@dataclass
class Subgraph:
    """处理用的中间图结构"""
    nodes: dict[str, Any] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    # 用于 DFS 的邻接表 (src -> [edges])
    _adj_list: dict[str, list[GraphEdge]] = field(default_factory=lambda: defaultdict(list))

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        self._adj_list[edge.src_uid].append(edge)


@dataclass
class ChainAnalysisResult:
    """LLM 分析结果的容器"""
    chain: List[GraphEdge]
    risk_score: float  # 0.0 - 1.0
    summary: str  # 攻击故事摘要
    tags: List[str]  # [Ransomware, Lateral Movement]
    mitre_id: str  # T1059


# ==========================================
# 3. LLM 分析器 (Prompt Engineering)
# ==========================================

class LLMChainAnalyzer:
    def __init__(self, context_mgr: ContextManager):
        self.ctx_mgr = context_mgr

    def _build_prompt(self, chain: List[GraphEdge]) -> str:
        """
        核心方法：将图链条转换为 Prompt 文本
        """
        timeline = []
        for i, edge in enumerate(chain):
            src_ctx = self.ctx_mgr.hydrate(edge.src_uid)
            dst_ctx = self.ctx_mgr.hydrate(edge.dst_uid)

            # 构建单步叙事
            step_desc = (
                f"STEP {i + 1} [Time: {edge.get_ts()}]:\n"
                f"  From: {src_ctx.description}\n"
                f"  Action: --[{edge.rtype.value}]-->\n"
                f"  To:   {dst_ctx.description}"
            )
            timeline.append(step_desc)

        narrative = "\n\n".join(timeline)

        # 提示词设计
        return f"""
You are a Senior Threat Hunter. Analyze the following execution chain for malicious activity.

CONTEXT (Execution Timeline):
--------------------------------------------------
{narrative}
--------------------------------------------------

INSTRUCTIONS:
1. Analyze the intent of the commands and relationships.
2. Look for patterns like Living-off-the-Land (LOLBins), C2 beacons, or Lateral Movement.
3. OUTPUT MUST BE STRICT JSON format with the following keys:
   - "risk_score": float (0.0 to 1.0)
   - "summary": string (concise explanation of what happened)
   - "attack_type": list of strings (e.g. ["Downloader", "Execution"])
   - "mitre_id": string (e.g. "T1059")

JSON RESPONSE:
"""

    def analyze(self, chain: List[GraphEdge]) -> ChainAnalysisResult:
        # 1. 构建 Prompt
        prompt = self._build_prompt(chain)

        # 2. 模拟调用 LLM (实际代码替换为 openai.ChatCompletion)
        # print(f"DEBUG PROMPT:\n{prompt}") 

        # --- Mock Response Logic (仅用于演示) ---
        # 如果链条里有 "powershell" 和 "connected"，模拟高风险
        chain_str = str([e.src_uid for e in chain]).lower()
        if "node_b" in chain_str:  # node_b 是 powershell
            mock_json = {
                "risk_score": 0.95,
                "summary": "Detected PowerShell executing encoded command to download payload from external IP.",
                "attack_type": ["Downloader", "Execution"],
                "mitre_id": "T1059.001"
            }
        else:
            mock_json = {
                "risk_score": 0.1,
                "summary": "Benign administrative activity.",
                "attack_type": [],
                "mitre_id": "N/A"
            }
        # ----------------------------------------

        return ChainAnalysisResult(
            chain=chain,
            risk_score=mock_json['risk_score'],
            summary=mock_json['summary'],
            tags=mock_json['attack_type'],
            mitre_id=mock_json['mitre_id']
        )


# ==========================================
# 4. 路径枚举 (DFS Algorithm)
# ==========================================


def extract_all_chains(subgraph: Subgraph, max_depth=10) -> List[List[GraphEdge]]:
    """
    使用 DFS 找出子图中所有的执行路径。
    适配 models.py 定义的 GraphEdge 和 Subgraph。
    """
    
    # --- 辅助函数：安全的获取时间戳 ---
    def get_edge_time(edge: GraphEdge) -> float:
        # 1. 优先尝试获取预处理好的浮点时间戳 (参见 api.py add_edge 逻辑)
        if "ts_float" in edge.props:
            return float(edge.props["ts_float"])
        
        # 2. 尝试获取字符串时间戳并解析
        ts_str = edge.get_ts()
        if ts_str:
            return _parse_ts_to_float(ts_str)
        
        # 3. 如果都没有，返回 0.0 (或者抛弃该边，视业务逻辑而定)
        return 0.0

    # 1. 寻找起点
    # 逻辑：在当前子图中，作为 src 出现过，但从未作为 dst 出现的点
    all_dsts = {e.dst_uid for e in subgraph.edges}
    start_nodes = {e.src_uid for e in subgraph.edges if e.src_uid not in all_dsts}

    # 兜底：如果是环状图（无明确起点），取时间最早那条边的源节点
    if not start_nodes and subgraph.edges:
        # 使用安全的 get_edge_time 进行排序
        sorted_edges = sorted(subgraph.edges, key=get_edge_time)
        start_nodes = {sorted_edges[0].src_uid}

    results = []

    def dfs(current_node_uid: str, current_path: List[GraphEdge]):
         
        # 终止条件1：路径深度限制 (防止遍历太深)
        if len(current_path) >= max_depth:
            results.append(list(current_path))
            return

        # 获取出边 (利用 Subgraph 的邻接表加速)
        # 注意：这里使用的是 src_uid 字符串索引，符合 Subgraph 定义
        outgoing_edges = subgraph._adj_list[current_node_uid]

        # 终止条件2：到达叶子节点 (没有出边)
        if not outgoing_edges:
            if current_path:
                results.append(list(current_path))
            return

        for edge in outgoing_edges:
            # --- 约束1：时序因果校验 ---
            # 后发生的操作时间必须 >= 前一个操作
            if current_path:
                last_edge = current_path[-1]
                last_ts = get_edge_time(last_edge)
                curr_ts = get_edge_time(edge)
                
                # 如果两个都有有效时间戳，且发生时间倒流，则跳过
                # (容忍 1.0秒的误差，防止日志采集微小乱序)
                if last_ts > 0 and curr_ts > 0 and curr_ts < (last_ts - 1.0):
                    continue

            # --- 约束2：防环路 (Cycle Detection) ---
            # 检查当前边的目标节点是否已经在路径中出现过
            if any(e.dst_uid == edge.dst_uid for e in current_path):
                continue
            
            # --- 递归 DFS ---
            current_path.append(edge)
            dfs(edge.dst_uid, current_path)
            current_path.pop() # 回溯

    # 对所有潜在起点发起搜索
    for start_node in start_nodes:
        dfs(start_node, [])

    return results


# ==========================================
# 5.图补全 (Phase B)
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
        seg_next = segs[i + 1]

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
            t_start=t_min - 1.0,  # 稍微放宽一点
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
            return None  # Drop this graph completely

        # 将找到的桥接边加入子图
        for edge in valid_bridges:
            edge.props['is_context'] = True  # 标记为补全边
            processing_sg.add_edge(edge)

    # 4. 最终连通性检查
    # 虽然我们要么是一个段，要么段之间都补上了边，但为了严谨（防止内部断裂），做一次全局检查
    if check_graph_connectivity(processing_sg):
        return processing_sg

    return None


# ==========================================
# 6. 主流程 (Main Pipeline)
# ==========================================


def run_killchain_pipeline_final() -> None:
    print("[*] Starting Context-Aware Kill Chain Analysis...")

    # --- 初始化基础设施 ---
    ctx_mgr = ContextManager()
    analyzer = LLMChainAnalyzer(ctx_mgr)

    # --- Phase A: FSA 状态机构建 (The Skeleton) ---
    print("[*] Phase A: Fetching alarms and building FSA...")
    abnormal_edges = get_alarm_edges()
    
    fsa_graphs: List[FSAGraph] = behavior_state_machine(abnormal_edges)
    print(f"[*] Phase A: Generated {len(fsa_graphs)} accepted FSA graphs.")

    valid_subgraphs: List[Subgraph] = []

    # --- Phase B: 图补全与连接 (The Flesh) ---
    print("[*] Phase B: Stitching segments and completing graphs...")
    for i, fsa_graph in enumerate(fsa_graphs):
        # 调用上面定义的连接函数
        subgraph = connect_fsa_segments(fsa_graph)
        
        if subgraph:
            print(f"  > Graph #{i} connected successfully ({len(subgraph.edges)} edges).")
            valid_subgraphs.append(subgraph)
        else:
            print(f"  > Graph #{i} discarded (disconnected segments).")

    # --- Phase C -> E: 路径提取与 AI 分析 (The Mind) ---
    final_reports = []
    
    for i, subgraph in enumerate(valid_subgraphs):
        print(f"\n--- Processing Subgraph #{i} ---")

        # Step 1: 提取所有路径 (DFS)
        potential_chains = extract_all_chains(subgraph)
        print(f"[*] Extracted {len(potential_chains)} potential chains.")

        # Step 2: 遍历路径进行 LLM 分析
        for chain_idx, chain in enumerate(potential_chains):
            # 剪枝：太短的链条忽略
            if len(chain) < 2: continue

            # Step 3: LLM 分析 (Hydrate -> Prompt -> Result)
            # 注意：analyze 内部会调用 hydrate，这可能会触发 DB 查询，
            # 所以 ContextManager 的缓存机制在这里非常重要。
            result = analyzer.analyze(chain)

            # Step 4: 结果过滤
            if result.risk_score > 0.7:
                print(f"  [ALERT] Chain #{chain_idx} High Risk! Score: {result.risk_score}")
                final_reports.append(result)

    # --- Phase F: 生成最终报告 (The Report) ---
    print("\n" + "=" * 50)
    print("FINAL SECURITY REPORT")
    print("=" * 50)

    if not final_reports:
        print("No high-risk threats detected.")

    for idx, report in enumerate(final_reports):
        print(f"\nincident_id: {idx + 1}")
        print(f"Threat Type: {report.tags} (MITRE: {report.mitre_id})")
        print(f"Risk Score:  {report.risk_score}")
        print(f"AI Summary:  {report.summary}")
        print("Evidence Chain:")
        for edge in report.chain:
            # 打印更详细的信息
            print(f"  [{edge.get_ts()}] {edge.src_uid} --{edge.rtype.value}--> {edge.dst_uid}")

if __name__ == "__main__":
    run_killchain_pipeline_final()