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
    
    def get_ts(self) -> Optional[str]:
        return self.props.get("@timestamp", 0)


# ---------- 2) 关系类型（枚举） ----------

class RelType(str, Enum):
    # 主机/网络
    COMMUNICATES_WITH = "COMMUNICATES_WITH"   # Host -> Host (netflow/zeek/suricata)
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

    def get_ts(self) -> Optional[str]:
        return self.props.get("@timestamp", 0)


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




class KillChainSubgraph:
    nodes_edges: List[Dict[str, Any]]  # [{'node': GraphNode, 'edge': GraphEdge|None}, ...]

    def __init__(self, nodes_edges: Optional[List[Dict[str, Any]]] = None):
        self.nodes_edges = nodes_edges or []

    def append_node_edge(self, node: GraphNode, edge: Optional[GraphEdge] = None):
        self.nodes_edges.append({"node": node, "edge": edge})

    def pop_node_edge(self) -> Tuple[GraphNode, Optional[GraphEdge]]:
        d = self.nodes_edges.pop()
        return d["node"], d["edge"]

    @classmethod
    def get_subgraph(cls, alarm_node: GraphNode) -> "KillChainSubgraph":
        """
        从 alarm_node 开始逆序回溯：
        - 当前节点记为 dst_node
        - 遍历所有入边：src_node -> dst_node
        - 仅保留 src.ts < dst.ts 的分支，否则剪枝
        - 回溯法：找到一条满足条件的链路就返回（你也可以改成收集全部分支）
        """
        path = cls(nodes_edges=[])
        path.append_node_edge(alarm_node, edge=None)  # 起点：告警节点，没有“指向下一跳”的边

        visited: Set[str] = set()  # 防环；按 uid 去重

        def dfs(dst_node: GraphNode, depth: int) -> bool:
            dst_uid = dst_node.uid
            if dst_uid in visited:
                # 防止环导致无限递归；是否剪枝可按需调整
                return False
            visited.add(dst_uid)

            # ---- 终止条件预留（不直接调用，避免 should_stop 里 pass 导致运行报错） ----
            # if should_stop(dst_node, depth, path):
            #     return True

            # 取出与 dst_node 相关的边；我们只取“入边”（src -> dst）
            all_edges = get_edges(dst_node) or []
            incoming = [e for e in all_edges if e.get_dst_uid() == dst_uid]

            dst_ts = dst_node.get_ts()

            for edge in incoming:
                src_node = get_node(edge.get_src_uid())
                if src_node is None:
                    # 数据不完整的剪枝留白
                    pass
                    continue

                src_ts = src_node.get_ts()

                # ---- 核心约束：src.ts < dst.ts（字符串比较）----
                if src_ts < dst_ts:
                    # ---- 其他剪枝预留（不直接调用，避免 should_prune 里 pass 导致运行报错）----
                    # if should_prune(edge, src_node, dst_node, depth):
                    #     continue

                    # 记录：src_node 通过 edge 指向当前 dst_node
                    path.append_node_edge(src_node, edge)

                    # 继续往前回溯
                    if dfs(src_node, depth + 1):
                        return True

                    # 回溯撤销
                    path.pop_node_edge()
                else:
                    # 不满足时间单调性：剪枝（按你要求保留 pass）
                    pass

            # 没有可继续的分支：自然结束（如果你想把“到头”当作成功终止，可在这里 return True）
            return False

        dfs(alarm_node, depth=0)

        return path
