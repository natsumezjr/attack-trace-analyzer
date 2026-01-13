from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha1
from typing import Any, Mapping, Tuple
from collections import defaultdict
import datetime

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

    # 返回节点 UID
    @property
    def uid(self) -> str:
        return build_uid(self.ntype, self.key)
    # 合并唯一键与属性字段
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

    # 获取边的时间戳
    def get_ts(self) -> str | None:
        return self.props.get("@timestamp") or self.props.get("ts")

    # 获取起点 UID
    def get_src_uid(self) -> str:
        return self.src_uid

    # 获取终点 UID
    def get_dst_uid(self) -> str:
        return self.dst_uid

    # 获取关系类型
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
        # 添加节点到子图
        self.nodes[node.uid] = node

    def add_edge(self, edge: GraphEdge) -> None:
        # 添加边并维护入边索引
        self.edges.append(edge)
        self._incoming_index[edge.dst_uid].append(edge)

    def get_node(self, uid: str) -> GraphNode | None:
        # 按 UID 获取节点
        return self.nodes.get(uid)

    # 获取指定节点的入边列表
    def get_incoming_edges(self, node_uid: str) -> list[GraphEdge]:
        """获取指向该节点的所有边 (用于回溯)"""
        return self._incoming_index[node_uid]

#    [重构后的KillChain] 纯数据类，只负责存储最终的攻击路径。
@dataclass
class CallChain:
    # 存储结构：直接存由边组成的有序列表，节点信息隐含在边中
    chain: list[GraphEdge] = field(default_factory=list)
    # 返回链路长度
    @property
    def length(self) -> int:
        return len(self.chain)


# ==========================================
# 分析流水线实现 (Pipeline Implementation)
# ==========================================

#### 1. 数据获取
# 从数据库拉取正常/异常边数据
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
    # 模拟语义分析，返回风险分数和特征向量
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
            # 允许 1秒 的时钟偏差 (skew tolerance)
            if prev_ts > curr_ts + 1.0: 
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
# 从链路中提取向量特征
def extract_vectors(chain: CallChain) -> list[list[float]]:
    vectors = []
    for edge in chain.chain:
        # 模拟：将 Edge 的属性 (rtype, props) 转化为向量
        v = [1.0, 0.5] 
        vectors.append(v)
    return vectors

#### 6.特征匹配
# 依据向量特征进行匹配并返回结果
def match_vector_features(vectors: list[list[float]]) -> dict[str, Any]:
    return {"attack_type": "Ransomware", "confidence": 0.98}

#### 7. LLM 分析
# 生成面向用户的分析文本
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

# 运行完整的分析流程
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
