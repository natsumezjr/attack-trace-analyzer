# graph_models.py
from __future__ import annotations
from enum import Enum
from hashlib import sha1
import json
from typing import Any, Dict, Optional, List

from pydantic import BaseModel, Field


# ---------- 1) 节点类型（枚举） ----------
class NodeType(str, Enum):
    HOST = "Host"
    USER = "User"
    SESSION = "Session"
    PROCESS = "Process"
    FILE = "File"
    DOMAIN = "Domain"
    
# ---------- 2) 关系类型（枚举） ----------

class RelType(str, Enum):
    # 主机/网络
    COMMUNICATES_WITH = "COMMUNICATES_WITH"   # Host -> Host (netflow/suricata)
    CONNECTS_TO = "CONNECTS_TO"               # Process/Host -> Endpoint/IP
    RESOLVES = "RESOLVES"                     # Host/Process -> Domain
    RESOLVES_TO = "RESOLVES_TO"               # Domain -> IP

    # 主机内部行为
    LOGON = "LOGON"                           # User -> Session
    ON_HOST = "ON_HOST"                       # Process/User/Session -> Host
    SPAWNED = "SPAWNED"                       # Process(parent) -> Process(child)
    ACCESSED = "ACCESSED"                     # Process -> File
    WROTE = "WROTE"                           # Process -> File

    # 关联/溯源输出
    SAME_ATTACK = "SAME_ATTACK"               # Event/Entity -> Event/Entity (聚类结果)
    CAUSED_BY = "CAUSED_BY"                   # Event -> Event (因果推断)
    MAPPED_TO_ATTACK = "MAPPED_TO_ATTACK"     # Event -> AttackStage(可选你们不建节点也行)


# ---------- 3) 统一的 UID 生成 ----------
def make_uid(ntype: NodeType, key: Dict[str, Any]) -> str:
    """
    给每个实体生成稳定唯一ID，避免重复入库。
    key 必须只放“能唯一标识这个实体”的字段。
    """
    raw = json.dumps(key, sort_keys=True, ensure_ascii=False)
    h = sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"{ntype.value}:{h}"


# ---------- 4) 节点 / 边的数据结构 ----------
class GraphNode(BaseModel):
    uid: str
    ntype: NodeType
    key: Dict[str, Any] = Field(default_factory=dict)      # 唯一键
    props: Dict[str, Any] = Field(default_factory=dict)    # 其它属性（可包含ECS字段子集）
    
    def get_uid(self) -> str:
        return self.uid
    
    def get_ntype(self) -> NodeType:
        return self.ntype
    
    def get_key(self) -> Dict[str, Any]:
        return self.key

class GraphEdge(BaseModel):
    src_uid: str
    dst_uid: str
    rtype: RelType
    # 关系属性：时间、证据源、ATT&CK标签、置信度等
    props: Dict[str, Any] = Field(default_factory=dict)
    
    def __init__(self, src_uid: str, dst_uid: str, rtype: RelType, props: Optional[Dict[str, Any]] = None):
        self.src_uid = src_uid
        self.dst_uid = dst_uid
        self.rtype = rtype
        self.props = props or {}
        
    def get_ts(self) -> Optional[str]:
        return self.props.get("@timestamp", 0)
    
    def get_src_uid(self) -> str:
        return self.src_uid
    
    def get_dst_uid(self) -> str:
        return self.dst_uid
    
    def get_rtype(self) -> RelType:
        return self.rtype


# ---------- 5) 你们确认的“实体键”规范 ----------
def host_node(host_name: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"host.name": host_name}
    return GraphNode(uid=make_uid(NodeType.HOST, key), ntype=NodeType.HOST, key=key, props=props or {})

def user_node(user_name: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"user.name": user_name}
    return GraphNode(uid=make_uid(NodeType.USER, key), ntype=NodeType.USER, key=key, props=props or {})

def session_node(host_name: str, session_id: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    # 注意：session_id 通常不是全局唯一，必须加 host 维度
    key = {"host.name": host_name, "session.id": session_id}
    return GraphNode(uid=make_uid(NodeType.SESSION, key), ntype=NodeType.SESSION, key=key, props=props or {})

def process_node(process_entity_id: Optional[str],
                 host_name: str,
                 pid: Optional[int],
                 start_ts: Optional[str],
                 props: Optional[Dict[str, Any]] = None) -> GraphNode:
    # 优先 process.entity_id；否则退化为 host+pid+start_ts
    if process_entity_id:
        key = {"process.entity_id": process_entity_id}
    else:
        key = {"host.name": host_name, "process.pid": pid, "process.start": start_ts}
    return GraphNode(uid=make_uid(NodeType.PROCESS, key), ntype=NodeType.PROCESS, key=key, props=props or {})

def file_node(path: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"file.path": path}
    return GraphNode(uid=make_uid(NodeType.FILE, key), ntype=NodeType.FILE, key=key, props=props or {})

def domain_node(dns_query: str, props: Optional[Dict[str, Any]] = None) -> GraphNode:
    key = {"dns.question.name": dns_query}
    return GraphNode(uid=make_uid(NodeType.DOMAIN, key), ntype=NodeType.DOMAIN, key=key, props=props or {})


from typing import Iterable, Mapping, Tuple, Set, Optional, Dict, Any, Union

# 可选：让 src/dst 既支持 GraphNode，也支持 uid 字符串
NodeOrUid = Union["GraphNode", str]

# ---------- 6) 关系两端类型约束（可按需增删） ----------
EDGE_TYPE_RULES: Dict[RelType, Tuple[Set[NodeType], Set[NodeType]]] = {
    # 主机/网络
    RelType.COMMUNICATES_WITH: ({NodeType.HOST}, {NodeType.HOST}),
    RelType.CONNECTS_TO: ({NodeType.PROCESS, NodeType.HOST}, {NodeType.ENDPOINT, NodeType.IP}),
    RelType.RESOLVES: ({NodeType.HOST, NodeType.PROCESS}, {NodeType.DOMAIN}),
    RelType.RESOLVES_TO: ({NodeType.DOMAIN}, {NodeType.IP}),

    # 主机内部行为
    RelType.LOGON: ({NodeType.USER}, {NodeType.SESSION}),
    RelType.ON_HOST: ({NodeType.PROCESS, NodeType.USER, NodeType.SESSION}, {NodeType.HOST}),
    RelType.SPAWNED: ({NodeType.PROCESS}, {NodeType.PROCESS}),
    RelType.ACCESSED: ({NodeType.PROCESS}, {NodeType.FILE}),
    RelType.WROTE: ({NodeType.PROCESS}, {NodeType.FILE}),

    # 关联/溯源输出（这里通常不强约束两端类型）
    # 你也可以按你们实际建模把 Event/AttackStage 加进 NodeType 再约束
    RelType.SAME_ATTACK: (set(NodeType), set(NodeType)),
    RelType.CAUSED_BY: (set(NodeType), set(NodeType)),
    RelType.MAPPED_TO_ATTACK: (set(NodeType), set(NodeType)),
}


def _uid_of(x: NodeOrUid) -> str:
    return x.uid if isinstance(x, GraphNode) else x


def _ntype_of(x: NodeOrUid) -> Optional[NodeType]:
    return x.ntype if isinstance(x, GraphNode) else None


def _validate_edge_types(rtype: RelType, src: NodeOrUid, dst: NodeOrUid) -> None:
    """
    只有当 src/dst 是 GraphNode 时才校验类型（如果你传入的是 uid 字符串，就跳过校验）。
    """
    src_t = _ntype_of(src)
    dst_t = _ntype_of(dst)
    if src_t is None or dst_t is None:
        return

    if rtype not in EDGE_TYPE_RULES:
        return

    allowed_src, allowed_dst = EDGE_TYPE_RULES[rtype]
    if src_t not in allowed_src or dst_t not in allowed_dst:
        raise ValueError(
            f"Invalid edge types for {rtype.value}: "
            f"{src_t.value} -> {dst_t.value}, "
            f"allowed: {sorted(t.value for t in allowed_src)} -> {sorted(t.value for t in allowed_dst)}"
        )


def make_edge(
    src: NodeOrUid,
    dst: NodeOrUid,
    rtype: RelType,
    props: Optional[Dict[str, Any]] = None,
    *,
    ts: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
    confidence: Optional[float] = None,
) -> GraphEdge:
    """
    通用边工厂：统一 props 注入（时间/证据/置信度）+ 关系两端类型校验。
    """
    _validate_edge_types(rtype, src, dst)

    p: Dict[str, Any] = {}
    if props:
        p.update(props)
    if ts is not None:
        p.setdefault("@timestamp", ts)  # 常见字段名，可按你们规范改
    if evidence is not None:
        p.setdefault("evidence", evidence)
    if confidence is not None:
        p.setdefault("confidence", confidence)

    return GraphEdge(
        src_uid=_uid_of(src),
        dst_uid=_uid_of(dst),
        rtype=rtype,
        props=p,
    )


def communicates_with(src_host: GraphNode, dst_host: GraphNode, **kw) -> GraphEdge:
    return make_edge(src_host, dst_host, RelType.COMMUNICATES_WITH, **kw)

def connects_to(src: GraphNode, dst: GraphNode, **kw) -> GraphEdge:
    return make_edge(src, dst, RelType.CONNECTS_TO, **kw)

def resolves(src: GraphNode, domain: GraphNode, **kw) -> GraphEdge:
    return make_edge(src, domain, RelType.RESOLVES, **kw)

def resolves_to(domain: GraphNode, ip: GraphNode, **kw) -> GraphEdge:
    return make_edge(domain, ip, RelType.RESOLVES_TO, **kw)

def logon(user: GraphNode, session: GraphNode, **kw) -> GraphEdge:
    return make_edge(user, session, RelType.LOGON, **kw)

def on_host(actor: GraphNode, host: GraphNode, **kw) -> GraphEdge:
    return make_edge(actor, host, RelType.ON_HOST, **kw)

def spawned(parent: GraphNode, child: GraphNode, **kw) -> GraphEdge:
    return make_edge(parent, child, RelType.SPAWNED, **kw)

def accessed(proc: GraphNode, file: GraphNode, **kw) -> GraphEdge:
    return make_edge(proc, file, RelType.ACCESSED, **kw)

def wrote(proc: GraphNode, file: GraphNode, **kw) -> GraphEdge:
    return make_edge(proc, file, RelType.WROTE, **kw)

def same_attack(a: GraphNode, b: GraphNode, **kw) -> GraphEdge:
    return make_edge(a, b, RelType.SAME_ATTACK, **kw)

def caused_by(effect: GraphNode, cause: GraphNode, **kw) -> GraphEdge:
    return make_edge(effect, cause, RelType.CAUSED_BY, **kw)

def mapped_to_attack(x: GraphNode, y: GraphNode, **kw) -> GraphEdge:
    return make_edge(x, y, RelType.MAPPED_TO_ATTACK, **kw)


from typing import Optional, Set, List, Tuple

# 假设在同一包内；按你们实际路径调整
from graph.api import get_edges, get_node




from typing import Any, Dict, Optional, List, Tuple, Set

from graph.api import get_edges, get_node
from models import GraphNode, GraphEdge


class KillChain:
    nodes_edges: List[Dict[str, Any]]  # [{'node': GraphNode, 'edge': GraphEdge|None}, ...]

    def __init__(self, nodes_edges: Optional[List[Dict[str, Any]]] = None):
        self.nodes_edges = nodes_edges or []

    def append_node_edge(self, node: GraphNode, edge: Optional[GraphEdge] = None):
        self.nodes_edges.append({"node": node, "edge": edge})

    def pop_node_edge(self) -> Tuple[GraphNode, Optional[GraphEdge]]:
        d = self.nodes_edges.pop()
        return d["node"], d["edge"]

    @classmethod
    def get_kill_chain(cls, alarm_edge: GraphEdge) -> "KillChain":
        """
        基于回溯法，从告警边 alarm_edge 开始逆序遍历：
        - 只沿“入边”回溯：prev_edge.dst_uid == curr_src_uid
        - 时间单调约束：prev_edge.ts < curr_edge.ts（字符串比较）
        - 不满足约束则剪枝（留白 pass）
        - 终止条件留白（should_stop 内 pass）
        """
        path = cls(nodes_edges=[])

        # ---- 内部留白：终止条件（你后续补）----
        def should_stop(curr_node: GraphNode, curr_edge: GraphEdge, depth: int) -> bool:
            """
            终止条件留白（按需实现）：
            - 深度达到上限
            - 回溯到“边界实体”（如 Host/User/某类节点）
            - 时间超出窗口
            - 命中特定关系类型
            """
            pass

        # ---- 内部留白：额外剪枝策略（你后续补）----
        def should_prune(prev_edge: GraphEdge, curr_edge: GraphEdge, depth: int) -> bool:
            """
            其他剪枝策略留白（按需实现）：
            - prev_edge 置信度过低
            - 关系类型不在允许集合
            - evidence/source 不可信
            - 白名单过滤
            """
            pass

        # 以 alarm_edge 为起点：先把“告警边的 dst 节点 + alarm_edge 本身 + src 节点”放入 path
        dst_node = get_node(alarm_edge.get_dst_uid())
        src_node = get_node(alarm_edge.get_src_uid())

        if dst_node is None or src_node is None:
            # 数据缺失：这里怎么处理你们定；先返回空/或部分
            # 留白
            pass
            return path

        # 约定：path 里每条记录是 “node + edge(从该 node 指向下一跳 node 的那条边)”
        # 所以先记录 dst_node（终点，edge=None），再记录 src_node（edge=alarm_edge 指向 dst_node）
        path.append_node_edge(dst_node, edge=None)
        path.append_node_edge(src_node, edge=alarm_edge)

        visited_edge: Set[Tuple[str, str, str]] = set()  # (src_uid, dst_uid, rtype) 防环；可按需增强

        def dfs(curr_node: GraphNode, curr_edge: GraphEdge, depth: int) -> bool:
            # 防止边循环
            src_uid = curr_edge.get_src_uid()
            dst_uid = curr_edge.get_dst_uid()
            rtype = curr_edge.get_rtype().value
            sig = (src_uid, dst_uid, rtype)
            if sig in visited_edge:
                return False
            visited_edge.add(sig)

            # ---- 终止条件预留：不直接调用（避免 should_stop 里 pass 导致运行报错）----
            # if should_stop(curr_node, curr_edge, depth):
            #     return True

            # 找所有与 curr_node 相关的边，再筛“入边”：prev_edge.dst_uid == curr_node.uid
            all_edges = get_edges(curr_node) or []
            incoming = []
            for e in all_edges:
                e_dst = e.get_dst_uid()
                if e_dst == curr_node.get_uid():
                    incoming.append(e)

            curr_ts = curr_edge.get_ts()

            for prev_edge in incoming:
                prev_ts = prev_edge.get_ts()

                # ---- 核心约束：prev_edge.ts < curr_edge.ts（字符串比较）----
                if prev_ts < curr_ts:
                    # ---- 额外剪枝预留：不直接调用（避免 should_prune 里 pass 导致运行报错）----
                    # if should_prune(prev_edge, curr_edge, depth):
                    #     continue

                    prev_src_uid = prev_edge.get_src_uid()
                    prev_src_node = get_node(prev_src_uid)
                    if prev_src_node is None:
                        # 数据缺失剪枝留白
                        pass
                        continue

                    # 记录：prev_src_node --prev_edge--> curr_node
                    path.append_node_edge(prev_src_node, edge=prev_edge)

                    if dfs(prev_src_node, prev_edge, depth + 1):
                        return True

                    # 回溯
                    path.pop_node_edge()
                else:
                    # 时间不满足：剪枝（留白 pass）
                    pass

            return False

        dfs(src_node, alarm_edge, depth=0)
        return path
