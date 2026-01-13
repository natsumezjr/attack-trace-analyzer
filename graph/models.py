from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha1
from typing import Any, Mapping

# 节点类型(主机节点、用户节点、进程节点、文件节点、IP节点、域名节点、网络连接节点)# 基础定义

# 枚举图内实体类型
class NodeType(str, Enum):
    HOST = "Host"
    USER = "User"
    PROCESS = "Process"
    FILE = "File"
    IP = "IP"
    DOMAIN = "Domain"
    NETCON = "NetConn"

# 枚举图内动作类型
class RelType(str, Enum):
    LOGON = "LOGON"
    SPAWNED = "SPAWNED"
    ACCESSED = "ACCESSED"
    CONNECTED = "CONNECTED"
    RESOLVED = "RESOLVED"
    RESOLVES_TO = "RESOLVES_TO"

# 每种节点类型的唯一键字段
    # 这里的定义是为例parase时简写时正确解析
    # uid = "Host:host.id=h-aaa" parse_uid(uid)
    # uid = "Host:h-aaa" parse_uid(uid)简写# 定义各节点的key字段
NODE_UNIQUE_KEY: dict[NodeType, str] = {
    NodeType.HOST: "host.id",
    NodeType.USER: "user.name",
    NodeType.PROCESS: "process.entity_id",
    NodeType.FILE: "file.path",
    NodeType.IP: "related.ip",
    NodeType.DOMAIN: "dns.question.name",
    NodeType.NETCON: "flow.id",
}

# 定义边的类型规则(每种边允许的源节点类型和目标节点类型)# 定义连接规则
EDGE_TYPE_RULES: dict[RelType, tuple[set[NodeType], set[NodeType]]] = {
    RelType.LOGON: ({NodeType.USER}, {NodeType.HOST}),
    RelType.SPAWNED: ({NodeType.PROCESS}, {NodeType.PROCESS}),
    RelType.ACCESSED: ({NodeType.PROCESS}, {NodeType.FILE}),
    RelType.CONNECTED: ({NodeType.PROCESS, NodeType.HOST, NodeType.NETCON}, {NodeType.IP, NodeType.NETCON}),
    RelType.RESOLVED: ({NodeType.HOST}, {NodeType.DOMAIN}),
    RelType.RESOLVES_TO: ({NodeType.DOMAIN}, {NodeType.IP}),
}

# 去重逻辑：避免因为数据源不同导致同一结点重复定义

# 辅助函数：生成唯一ID(hash前16位)
def _sha1_hex(raw: str) -> str:
    return sha1(raw.encode("utf-8")).hexdigest()[:16]

# 生成Host ID# host_id生成
def make_host_id(host_name: str) -> str:
    return f"h-{_sha1_hex(host_name)}"
# process_entity_id生成# 生成进程 ID(主机+PID+启动时间+执行路径 定义)
def make_process_entity_id(host_id: str, pid: int, start_ts: str, executable: str) -> str:
    raw = f"{host_id}:{pid}:{start_ts}:{executable}"
    return f"p-{_sha1_hex(raw)}"

# 给类的实例创建唯一标识符uid
# UID 是一个字符串，格式固定："<Label>:key=value;k=v"
# 前缀是节点类型（Host/User/Process/...）
# 后面是若干个 k=v（key field = value），用来表达这个节点的唯一键

# 构建 UID 字符串
def build_uid(ntype: NodeType, key: Mapping[str, Any]) -> str:
    items = [(k, v) for k, v in key.items() if v is not None]
    if not items:
        raise ValueError("Node key must include at least one field.")
    items.sort(key=lambda kv: kv[0])
    if len(items) == 1:
        k, v = items[0]
        return f"{ntype.value}:{k}={v}"
    payload = ";".join(f"{k}={v}" for k, v in items)
    return f"{ntype.value}:{payload}"

# 解析 UID 字符串，返回节点类型和唯一键字典# 基于标识符获得类的实例
def parse_uid(uid: str) -> tuple[NodeType, dict[str, Any]]:
    if ":" not in uid:
        raise ValueError(f"Invalid uid format: {uid}")
    label_raw, rest = uid.split(":", 1)
    try:
        label = NodeType(label_raw)
    except ValueError as exc:
        raise ValueError(f"Unknown node label in uid: {uid}") from exc

    if "=" in rest:
        key: dict[str, Any] = {}
        for chunk in rest.split(";"):
            if not chunk:
                continue
            k, v = chunk.split("=", 1)
            key[k] = v
        if not key:
            raise ValueError(f"Empty key in uid: {uid}")
        return label, key

    key_field = NODE_UNIQUE_KEY[label]
    return label, {key_field: rest}


# GraphNode节点数据结构
    # 节点类型ntype
    # 唯一键key
    # 其他属性props
    # merged_props方法将key和props合并，key中的非None值优先级更高。
# 图的节点定义
@dataclass
class GraphNode:
    ntype: NodeType
    key: dict[str, Any]
    props: dict[str, Any] = field(default_factory=dict)

    @property
    def uid(self) -> str:
        return build_uid(self.ntype, self.key)
    def merged_props(self) -> dict[str, Any]:
        merged = dict(self.props)
        for k, v in self.key.items():
            if v is not None:
                merged.setdefault(k, v)
        return merged

# 图的边定义
# GraphEdge边数据结构
    # 源节点UID src_uid
    # 目标节点UID dst_uid
    # 关系类型rtype
    # 其他属性props(其他攻击相关属性)
@dataclass
class GraphEdge:
    src_uid: str
    dst_uid: str
    rtype: RelType
    props: dict[str, Any] = field(default_factory=dict)

    def get_ts(self) -> str | None:
        return self.props.get("@timestamp") or self.props.get("ts")

    def get_src_uid(self) -> str:
        return self.src_uid

    def get_dst_uid(self) -> str:
        return self.dst_uid

    def get_rtype(self) -> RelType:
        return self.rtype

# 主机节点
    # host_id 主机ID
    # host_name 主机名称
    # props 其他属性
    # 这里是host_id若没有传则是以hostname生成的，假设系统内设置的主机名唯一# 主机节点定义
def host_node(
    host_id: str | None = None,
    host_name: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if host_id is None and host_name is None:
        raise ValueError("host_id or host_name is required.")
    if host_id is None:
        host_id = make_host_id(host_name)
    node_props = dict(props or {})
    if host_name:
        node_props.setdefault("host.name", host_name)
    return GraphNode(ntype=NodeType.HOST, key={"host.id": host_id}, props=node_props)

# 用户节点
    # user_name 用户名称
    # user_id 用户ID
def user_node(
    user_name: str | None = None,
    user_id: str | None = None,
    *,
    host_id: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if user_name is None and user_id is None:
        raise ValueError("user_name or user_id is required.")
    node_props = dict(props or {})
    node_props = dict(props or {})

    if user_name is not None:
        node_props.setdefault("user.name", user_name)
    if user_id is not None:
        node_props.setdefault("user.id", user_id)
    if host_id is not None:
        node_props.setdefault("host.id", host_id)
    if user_id:
        return GraphNode(
            ntype=NodeType.USER,
            key={"user.id": user_id},
            props=node_props,
        )

    if not user_name:
        raise ValueError("user_name is required when user_id is missing.")
    if not host_id:
        raise ValueError("host_id is required when user_id is missing (to scope user_name).")

    return GraphNode(
        ntype=NodeType.USER,
        key={"host.id": host_id, "user.name": user_name},
        props=node_props,
    )

# 进程节点定义
    # process_entity_id 进程实体ID
    # pid 进程ID
    # executable 可执行文件路径
    # command_line 命令行
    # name 进程名称
    # host_id 主机ID
    # start_time 进程启动时间
def process_node(
    process_entity_id: str | None = None,
    *,
    pid: int | None = None,
    executable: str | None = None,
    command_line: str | None = None,
    name: str | None = None,
    host_id: str | None = None,
    start_time: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if process_entity_id is None:
        if host_id is None or pid is None or executable is None or (start_time is None):
            raise ValueError("process_entity_id or (host_id, pid, executable, start_time) is required.")
        process_entity_id = make_process_entity_id(host_id, pid, start_time, executable)
    node_props = dict(props or {})
    node_props.setdefault("process.entity_id", process_entity_id)
    if pid is not None:
        node_props.setdefault("process.pid", pid)
    if executable:
        node_props.setdefault("process.executable", executable)
    if command_line:
        node_props.setdefault("process.command_line", command_line)
    if name:
        node_props.setdefault("process.name", name)
    if host_id:
        node_props.setdefault("host.id", host_id)
    if start_time:
        node_props.setdefault("process.start", start_time)
    return GraphNode(ntype=NodeType.PROCESS, key={"process.entity_id": process_entity_id}, props=node_props)


# 文件节点定义
def file_node(
    path: str | None = None,
    hash_sha256: str | None = None,
    hash_sha1: str | None = None,
    hash_md5: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    if path is None and hash_sha256 is None and hash_sha1 is None and hash_md5 is None:
        raise ValueError("file.path or file.hash.* is required.")
    node_props = dict(props or {})
    if path:
        node_props.setdefault("file.path", path)
    if hash_sha256:
        node_props.setdefault("file.hash.sha256", hash_sha256)
    if hash_sha1:
        node_props.setdefault("file.hash.sha1", hash_sha1)
    if hash_md5:
        node_props.setdefault("file.hash.md5", hash_md5)
    if path:
        key = {"file.path": path}
    elif hash_sha256:
        key = {"file.hash.sha256": hash_sha256}
    elif hash_sha1:
        key = {"file.hash.sha1": hash_sha1}
    else:
        key = {"file.hash.md5": hash_md5}
    return GraphNode(ntype=NodeType.FILE, key=key, props=node_props)

# IP节点定义
def ip_node(addr: str, props: dict[str, Any] | None = None) -> GraphNode:
    if not addr:
        raise ValueError("ip address is required.")
    node_props = dict(props or {})
    node_props.setdefault("related.ip", addr)
    return GraphNode(ntype=NodeType.IP, key={"related.ip": addr}, props=node_props)

# 域名节点定义
def domain_node(dns_name: str | None = None, url_domain: str | None = None, props: dict[str, Any] | None = None) -> GraphNode:
    if not dns_name and not url_domain:
        raise ValueError("dns.question.name or url.domain is required.")
    node_props = dict(props or {})
    if dns_name:
        node_props.setdefault("dns.question.name", dns_name)
    if url_domain:
        node_props.setdefault("url.domain", url_domain)
    key = {"dns.question.name": dns_name} if dns_name else {"url.domain": url_domain}
    return GraphNode(ntype=NodeType.DOMAIN, key=key, props=node_props)


# 网络连接节点定义
def netcon_node(
    flow_id: str | None = None,
    community_id: str | None = None,
    source_ip: str | None = None,
    source_port: int | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    transport: str | None = None,
    protocol: str | None = None,
    props: dict[str, Any] | None = None,
) -> GraphNode:
    # NetConn 使用 flow/community id 作为唯一键，对齐 ECS 的会话语义。
    if flow_id is None and community_id is None:
        raise ValueError("flow.id or network.community_id is required.")
    node_props = dict(props or {})
    if flow_id:
        node_props.setdefault("flow.id", flow_id)
    if community_id:
        node_props.setdefault("network.community_id", community_id)
    if source_ip:
        node_props.setdefault("source.ip", source_ip)
    if source_port is not None:
        node_props.setdefault("source.port", source_port)
    if destination_ip:
        node_props.setdefault("destination.ip", destination_ip)
    if destination_port is not None:
        node_props.setdefault("destination.port", destination_port)
    if transport:
        node_props.setdefault("network.transport", transport)
    if protocol:
        node_props.setdefault("network.protocol", protocol)
    key = {"flow.id": flow_id} if flow_id else {"network.community_id": community_id}
    return GraphNode(ntype=NodeType.NETCON, key=key, props=node_props)


NodeOrUid = GraphNode | str

# 辅助函数：传入节点对象或者ID字符串，返回ID字符串
def _uid_of(x: NodeOrUid) -> str:
    return x.uid if isinstance(x, GraphNode) else x

# 辅助函数：传入节点对象或者ID字符串，返回节点类型
def _ntype_of(x: NodeOrUid) -> NodeType | None:
    if isinstance(x, GraphNode):
        return x.ntype
    if isinstance(x, str):
        try:
            return parse_uid(x)[0]
        except ValueError:
            return None
    return None

# 强制执行图谱的Schema规则，避免边连接不合法的节点
def _validate_edge_types(rtype: RelType, src: NodeOrUid, dst: NodeOrUid) -> None:
    src_t = _ntype_of(src)
    dst_t = _ntype_of(dst)  
    if src_t is None or dst_t is None:
        return
    rules = EDGE_TYPE_RULES.get(rtype)
    if not rules:
        return
    allowed_src, allowed_dst = rules
    if src_t not in allowed_src or dst_t not in allowed_dst:
        raise ValueError(
            f"Invalid edge types for {rtype.value}: "
            f"{src_t.value} -> {dst_t.value}, "
            f"allowed: {sorted(t.value for t in allowed_src)} -> {sorted(t.value for t in allowed_dst)}"
        )

# 通用边工厂函数
def make_edge(
    src: NodeOrUid,
    dst: NodeOrUid,
    rtype: RelType,
    props: dict[str, Any] | None = None,
    *,
    ts: str | None = None,
    evidence_event_ids: list[str] | None = None,
    weight: float | None = None,
) -> GraphEdge:
    _validate_edge_types(rtype, src, dst)
    edge_props: dict[str, Any] = dict(props or {})
    if ts is not None:
        edge_props.setdefault("@timestamp", ts)
    if evidence_event_ids is not None:
        edge_props.setdefault("custom.evidence.event_ids", evidence_event_ids)
    if weight is not None:
        edge_props.setdefault("weight", weight)
    return GraphEdge(
        src_uid=_uid_of(src),
        dst_uid=_uid_of(dst),
        rtype=rtype,
        props=edge_props,
    )

# 语义化封装

# 用户登录主机
def logon(user: GraphNode, host: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(user, host, RelType.LOGON, **kw)

# 进程衍生子进程
def spawned(parent: GraphNode, child: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(parent, child, RelType.SPAWNED, **kw)

# 进程访问文件
def accessed(proc: GraphNode, file: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(proc, file, RelType.ACCESSED, **kw)

# 网络连接
def connected(src: GraphNode, dst: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(src, dst, RelType.CONNECTED, **kw)

# 主机解析域名
def resolved(host: GraphNode, domain: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(host, domain, RelType.RESOLVED, **kw)

# 域名解析到IP
def resolves_to(domain: GraphNode, ip: GraphNode, **kw: Any) -> GraphEdge:
    return make_edge(domain, ip, RelType.RESOLVES_TO, **kw)


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

# 1. 数据获取
def fetch_edges_from_db() -> tuple[list[GraphEdge], list[GraphEdge]]:
    return [], []

# 2. 状态机 (构建初步子图)
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

# 3. 子图补全
def expand_to_complete_subgraph(subgraph: Subgraph) -> Subgraph:
    """
    逻辑：拿到 subgraph 里的所有 node uid，去数据库查它们之间漏掉的边，
    加回到 subgraph 对象中，使其“完全连通”。
    """
    # 模拟：此处应该调用 database API 查找更多关联边
    # new_edges = db.find_edges_between(subgraph.nodes.keys())
    # for e in new_edges: subgraph.add_edge(e)
    return subgraph

# 4. 溯源分析
def backtrack_call_chain(subgraph: Subgraph, alarm_edge: GraphEdge | None = None) -> CallChain:
    
    # 如果没指定从哪条边开始，默认取子图里时间最晚的边作为告警边
    if alarm_edge is None:
        if not subgraph.edges:
            return CallChain()
        # 假设按时间排序取最后一个
        alarm_edge = subgraph.edges[-1] 

    path_stack: list[GraphEdge] = [alarm_edge]
    visited: set[tuple[str, str, str]] = set()

    # 结果容器
    final_chain = CallChain()

    def should_prune(prev: GraphEdge, curr: GraphEdge) -> bool:
        # 实现具体的剪枝逻辑
        return False

    def dfs(curr_edge: GraphEdge) -> bool:
        """
        递归寻找攻击链
        """
        sig = (curr_edge.src_uid, curr_edge.dst_uid, curr_edge.rtype.value)
        if sig in visited:
            return False
        visited.add(sig)

        curr_src_uid = curr_edge.src_uid
        
        # 直接从 subgraph 对象获取入边，而不是调 API
        incoming_edges = subgraph.get_incoming_edges(curr_src_uid)
        
        curr_ts = curr_edge.get_ts()

        # 标记位(含义）：有没有找到更上游的原因
        found_upstream = False
        for prev_edge in incoming_edges:
            prev_ts = prev_edge.get_ts()
            
            # 时间因果律检查
            if curr_ts and prev_ts and prev_ts < curr_ts:
                if should_prune(prev_edge, curr_edge):
                    continue
                
                path_stack.append(prev_edge)
                if dfs(prev_edge):
                    found_upstream = True
                    # 这里可以选择是否找到一条就返回，或者通过某种逻辑保留最长路径
                    # 简单起见，我们保留最深的那条路径
                    pass 
                
                # 如果是回溯算法，通常需要 pop，但在寻找“最长攻击链”时，
                # 我们往往在递归到底部（叶子节点）时保存快照。
                # 此处简化逻辑：如果找到了更上游的，就不从这里断开
                if not found_upstream:
                    path_stack.pop() 
        
        return found_upstream

    # 启动 DFS
    dfs(alarm_edge)
    
    # 将栈转换为结果 (注意 DFS 栈的顺序是倒序的：告警 -> 原因 -> 更早的原因)
    # 通常我们习惯看：原因 -> 结果，所以反转一下
    final_chain.chain = list(reversed(path_stack))
    
    return final_chain

# 5. 向量提取
def extract_vectors(chain: CallChain) -> list[list[float]]:
    vectors = []
    for edge in chain.chain:
        # 模拟：将 Edge 的属性 (rtype, props) 转化为向量
        v = [1.0, 0.5] 
        vectors.append(v)
    return vectors

# 6. 特征匹配
def match_vector_features(vectors: list[list[float]]) -> dict[str, Any]:
    return {"attack_type": "Ransomware", "confidence": 0.98}

# 7. LLM 分析
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