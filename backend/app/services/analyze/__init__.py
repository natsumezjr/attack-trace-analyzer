from .killchain import KillChain, run_killchain_pipeline
from .killchain_llm import create_llm_client
from typing import List
import json
from pathlib import Path

def analyze_killchain(kc_uuid: str) -> List[KillChain]:
    import os
    llm_provider = os.getenv("LLM_PROVIDER", "not_set")
    has_api_key = bool(os.getenv("DEEPSEEK_API_KEY"))
    print(f"[DEBUG] analyze_killchain: LLM_PROVIDER={llm_provider}, has_api_key={has_api_key}")
    
    try:
        load_test_fsa_to_database()
        llm_client = create_llm_client()
        client_type = type(llm_client).__name__
        print(f"[DEBUG] LLM client created: {client_type}")
        
        # 检查 client 是否有 choose 方法
        if hasattr(llm_client, "choose"):
            print(f"[DEBUG] LLM client has choose method")
        else:
            print(f"[DEBUG] WARNING: LLM client does NOT have choose method")
            
        # 如果是 MockChooser，说明使用了 mock 模式
        if client_type == "MockChooser":
            print(f"[DEBUG] Using MockChooser (mock mode)")
        elif client_type == "LLMChooser":
            print(f"[DEBUG] Using LLMChooser (real LLM mode)")
            # 检查 chat_complete 是否设置
            if hasattr(llm_client, "chat_complete"):
                if llm_client.chat_complete is None:
                    print(f"[DEBUG] WARNING: LLMChooser.chat_complete is None")
                else:
                    print(f"[DEBUG] LLMChooser.chat_complete is set")
    except Exception as e:
        print(f"[killchain] 无法创建 LLM client: {e}，使用 fallback")
        import traceback
        traceback.print_exc()
        llm_client = None
    
    kcs = run_killchain_pipeline(kc_uuid=kc_uuid, llm_client=llm_client, persist=True)
    return kcs


def load_test_fsa_to_database() -> tuple[int, int]:
    """
    加载测试 FSA 数据（testFSA.json）到 Neo4j 数据库
    
    流程：
    1. 初始化 Neo4j schema
    2. 加载测试数据
    3. 清理旧测试数据
    4. 导入数据到 Neo4j
    
    Returns:
        tuple[int, int]: (节点数, 边数)
    """
    from ..neo4j import db as graph_db
    from ..neo4j import ingest as graph_ingest
    
    # 1. 初始化 Neo4j schema
    print("[加载测试数据] 初始化 Neo4j schema...")
    graph_db.ensure_schema()
    print("✓ Schema 初始化完成")
    
    # 2. 加载测试数据
    print("[加载测试数据] 加载测试数据...")
    backend_dir = Path(__file__).resolve().parent.parent.parent
    fixture_path = backend_dir / "tests" / "fixtures" / "graph" / "testFSA.json"
    
    if not fixture_path.exists():
        raise FileNotFoundError(f"测试数据文件不存在: {fixture_path}")
    
    print(f"正在读取测试数据: {fixture_path}")
    with open(fixture_path, "r", encoding="utf-8") as f:
        events = json.load(f)
    
    if not isinstance(events, list):
        raise ValueError(f"测试数据格式错误: 期望 list，得到 {type(events)}")
    
    print(f"成功加载 {len(events)} 条事件")
    
    # 3. 清理旧数据
    print("[加载测试数据] 清理旧测试数据...")
    _delete_existing_test_data(events)
    print("✓ 清理完成")
    
    # 4. 导入数据
    print("[加载测试数据] 导入数据到 Neo4j...")
    node_count, edge_count = graph_ingest.ingest_ecs_events(events)
    print(f"✓ 导入完成: {node_count} 个节点, {edge_count} 条边")
    
    return node_count, edge_count


def _delete_existing_test_data(events: list[dict]) -> None:
    """
    删除与测试事件相关的现有数据，避免重复
    
    Args:
        events: 测试事件列表
    """
    from ..neo4j import db as graph_db
    
    event_ids = [e.get("event", {}).get("id") for e in events if e.get("event", {}).get("id")]
    host_ids = set()
    user_ids = set()
    
    for event in events:
        host_id = event.get("host", {}).get("id")
        if host_id:
            host_ids.add(host_id)
        user_id = event.get("user", {}).get("id")
        if user_id:
            user_ids.add(user_id)
    
    with graph_db._get_session() as session:
        if event_ids:
            session.run("MATCH ()-[r]->() WHERE r.`event.id` IN $ids DELETE r", ids=event_ids)
            print(f"[清理] 删除了 {len(event_ids)} 条边（通过 event.id）")
        if user_ids:
            session.run("MATCH (n:User) WHERE n.`user.id` IN $user_ids DETACH DELETE n", user_ids=list(user_ids))
            print(f"[清理] 删除了 {len(user_ids)} 个 User 节点")
        if host_ids:
            session.run("MATCH (n:Host) WHERE n.`host.id` IN $host_ids DETACH DELETE n", host_ids=list(host_ids))
            session.run("MATCH (n:Process) WHERE n.`host.id` IN $host_ids DETACH DELETE n", host_ids=list(host_ids))
            session.run("MATCH (n:File) WHERE n.`host.id` IN $host_ids DETACH DELETE n", host_ids=list(host_ids))
            print(f"[清理] 删除了 {len(host_ids)} 个主机的相关节点")

__all__ = ["analyze_killchain"]
