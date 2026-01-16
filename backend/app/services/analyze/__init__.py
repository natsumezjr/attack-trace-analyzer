from .killchain import KillChain, run_killchain_pipeline
from .killchain_llm import create_llm_client
from typing import List
import json
from pathlib import Path

# 确保导入 config 模块，触发 .env 文件加载
from app.core.config import settings

def analyze_killchain(kc_uuid: str) -> List[KillChain]:
    # 使用 settings 而不是直接使用 os.getenv，确保 .env 文件已被加载
    llm_provider = settings.llm_provider
    api_key = settings.llm_api_key
    has_api_key = bool(api_key)
    
    # 强制要求使用真实大模型
    if llm_provider.lower() == "mock" or not has_api_key:
        error_msg = (
            "❌ 错误：killchain 测试必须使用真实大模型！\n"
            f"当前配置: LLM_PROVIDER={llm_provider}, DEEPSEEK_API_KEY={'已设置' if has_api_key else '未设置'}\n\n"
            "请设置以下环境变量：\n"
            "  export LLM_PROVIDER=deepseek\n"
            "  export DEEPSEEK_API_KEY=your_api_key_here\n\n"
            "或者在 backend/.env 文件中添加：\n"
            "  LLM_PROVIDER=deepseek\n"
            "  DEEPSEEK_API_KEY=your_api_key_here\n\n"
            "设置后请重启后端服务。"
        )
        raise ValueError(error_msg)
    
    try:
        load_test_fsa_to_database()
        # 强制使用 deepseek provider
        llm_client = create_llm_client(provider="deepseek", api_key=api_key)
        client_type = type(llm_client).__name__
        
        # 如果是 MockChooser，说明配置有问题
        if client_type == "MockChooser":
            raise ValueError(
                "❌ 错误：创建了 MockChooser 而不是真实 LLM！\n"
                "请检查 DEEPSEEK_API_KEY 是否正确设置。"
            )
        elif client_type == "LLMChooser":
            # 检查 chat_complete 是否设置
            if hasattr(llm_client, "chat_complete"):
                if llm_client.chat_complete is None:
                    raise ValueError("LLMChooser.chat_complete is None，无法调用真实LLM")
    except ValueError as e:
        # 重新抛出配置错误
        raise
    except Exception as e:
        error_msg = (
            f"❌ 无法创建 LLM client: {e}\n\n"
            "请检查：\n"
            "1. DEEPSEEK_API_KEY 是否正确\n"
            "2. 网络连接是否正常\n"
            "3. 是否安装了 openai 库: uv add openai 或 pip install openai"
        )
        import traceback
        traceback.print_exc()
        raise RuntimeError(error_msg) from e
    
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
    # 从 backend/app/services/analyze/__init__.py 向上4层到 backend 目录
    # __file__ = backend/app/services/analyze/__init__.py
    # parents[0] = backend/app/services/analyze/
    # parents[1] = backend/app/services/
    # parents[2] = backend/app/
    # parents[3] = backend/
    current_file = Path(__file__).resolve()
    backend_dir = current_file.parents[3]  # 使用 parents[3] 更可靠
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
