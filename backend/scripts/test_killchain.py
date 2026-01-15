#!/usr/bin/env python3
"""
KillChain 测试脚本（不含 LLM）

专门用于测试 KillChain 流水线（Phase A -> Phase B -> Phase C），不依赖 LLM。
测试流程：
1. 导入测试数据到 Neo4j
2. 运行完整的 killchain 流水线（llm_client=None，使用 fallback）
3. 输出结果分析

用法:
    python scripts/test_killchain.py
    或
    docker compose exec python python scripts/test_killchain.py
"""

import json
import sys
import uuid
from pathlib import Path
from typing import List

# 添加项目根目录到 Python 路径
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.neo4j import db as graph_db
from app.services.neo4j import ingest as graph_ingest
from app.services.analyze.killchain import run_killchain_pipeline, KillChain
from app.services.analyze.attack_fsa import AttackState


def load_test_events() -> list[dict]:
    """从 testFSA.json 加载测试事件"""
    fixture_path = backend_dir / "tests" / "fixtures" / "graph" / "testFSA.json"
    
    if not fixture_path.exists():
        raise FileNotFoundError(f"测试数据文件不存在: {fixture_path}")
    
    print(f"正在读取测试数据: {fixture_path}")
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        raise ValueError(f"测试数据格式错误: 期望 list，得到 {type(data)}")
    
    print(f"成功加载 {len(data)} 条事件")
    return data


def delete_existing_test_data(events: list[dict]) -> None:
    """删除与测试事件相关的现有数据，避免重复"""
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
    graph_db.close()


def print_killchain_summary(killchains: List[KillChain]) -> None:
    """打印 KillChain 结果摘要"""
    print("\n" + "=" * 60)
    print("KillChain 分析结果")
    print("=" * 60)
    
    if not killchains:
        print("❌ 未生成任何 KillChain")
        return
    
    print(f"✓ 生成了 {len(killchains)} 个 KillChain\n")
    
    for i, kc in enumerate(killchains, 1):
        print(f"--- KillChain #{i} ---")
        print(f"UUID: {kc.kc_uuid}")
        print(f"FSA 节点数: {len(kc.fsa_graph.nodes) if kc.fsa_graph else 0}")
        print(f"状态段数: {len(kc.segments) if kc.segments else 0}")
        print(f"选中路径数: {len(kc.selected_paths)}")
        print(f"可信度: {kc.confidence:.2f}")
        print(f"解释: {kc.explanation[:100]}..." if kc.explanation else "解释: (无)")
        
        # 显示状态序列
        if kc.segments:
            states = [seg.state for seg in kc.segments]  # seg.state 已经是字符串，不需要 .value
            print(f"状态序列: {' -> '.join(states)}")
        
        # 显示选中的路径
        if kc.selected_paths:
            print(f"\n选中的路径:")
            for j, path in enumerate(kc.selected_paths, 1):
                print(f"  Path #{j}: {path.path_id}")
                print(f"    - 源锚点: {path.src_anchor}")
                print(f"    - 目标锚点: {path.dst_anchor}")
                print(f"    - 边数: {len(path.edges)}")
                print(f"    - 步骤数: {len(path.steps)}")
        else:
            print("⚠️  没有选中的路径（可能是单段 killchain）")
        
        print()


def analyze_killchain_results(killchains: List[KillChain]) -> None:
    """分析 KillChain 结果，验证是否正确构建了攻击链"""
    print("\n" + "=" * 60)
    print("KillChain 结果验证")
    print("=" * 60)
    
    expected_states = [
        AttackState.INITIAL_ACCESS.value,
        AttackState.EXECUTION.value,
        AttackState.PRIVILEGE_ESCALATION.value,
        AttackState.LATERAL_MOVEMENT.value,
        AttackState.COMMAND_AND_CONTROL.value,
        AttackState.IMPACT.value,
    ]
    
    found_valid_chain = False
    
    for i, kc in enumerate(killchains, 1):
        if not kc.segments:
            print(f"⚠️  KillChain #{i}: 没有状态段")
            continue
        
        states = [seg.state for seg in kc.segments]  # seg.state 已经是字符串，不需要 .value
        
        # 检查是否包含所有期望的状态
        missing_states = [s for s in expected_states if s not in states]
        if missing_states:
            print(f"⚠️  KillChain #{i}: 缺少状态 {missing_states}")
        else:
            print(f"✅ KillChain #{i}: 包含所有期望的状态")
            found_valid_chain = True
        
        # 检查是否有选中的路径（除了单段情况）
        if len(kc.segments) > 1 and not kc.selected_paths:
            print(f"⚠️  KillChain #{i}: 有多个段但没有选中的路径")
        elif len(kc.segments) > 1 and kc.selected_paths:
            print(f"✅ KillChain #{i}: 有 {len(kc.selected_paths)} 条选中的路径")
    
    if not found_valid_chain:
        print("\n❌ 未找到包含所有期望状态的 KillChain")
    else:
        print("\n✅ 测试通过：KillChain 流水线正确构建了攻击链")


def main():
    """主函数"""
    print("=" * 60)
    print("KillChain 测试（不含 LLM）")
    print("=" * 60)
    
    try:
        # 1. 初始化 Neo4j schema
        print("\n[1/5] 初始化 Neo4j schema...")
        graph_db.ensure_schema()
        print("✓ Schema 初始化完成")
        
        # 2. 加载测试数据
        print("\n[2/5] 加载测试数据...")
        events = load_test_events()
        
        # 3. 清理旧数据
        print("\n[3/5] 清理旧测试数据...")
        delete_existing_test_data(events)
        print("✓ 清理完成")
        
        # 4. 导入数据
        print("\n[4/5] 导入数据到 Neo4j...")
        node_count, edge_count = graph_ingest.ingest_ecs_events(events)
        print(f"✓ 导入完成: {node_count} 个节点, {edge_count} 条边")
        
        # 5. 运行 KillChain 流水线（不含 LLM）
        print("\n[5/5] 运行 KillChain 流水线（llm_client=None，使用 fallback）...")
        kc_uuid = str(uuid.uuid4())
        print(f"KillChain UUID: {kc_uuid}")
        
        killchains = run_killchain_pipeline(
            kc_uuid=kc_uuid,
            llm_client=None,  # 不使用 LLM，使用 fallback
            persist=True
        )
        
        # 6. 输出结果
        print_killchain_summary(killchains)
        analyze_killchain_results(killchains)
        
        # 7. 显示 Neo4j 查询示例
        if killchains:
            best_kc = max(killchains, key=lambda kc: kc.confidence)
            print("\n" + "=" * 60)
            print("Neo4j 浏览器查询示例")
            print("=" * 60)
            print(f"\n访问 Neo4j 浏览器: http://localhost:7474")
            print(f"\n查询 KillChain (UUID: {best_kc.kc_uuid}):")
            print("-" * 60)
            print(f"""MATCH (n)-[r]->(m)
WHERE n.`analysis.task_id` = '{best_kc.kc_uuid}'
   OR r.`analysis.task_id` = '{best_kc.kc_uuid}'
   OR m.`analysis.task_id` = '{best_kc.kc_uuid}'
RETURN n, r, m
LIMIT 100""")
        
        print("\n" + "=" * 60)
        print("测试完成！")
        print("=" * 60)
        print(f"\n统计信息:")
        print(f"  - 事件数: {len(events)}")
        print(f"  - 节点数: {node_count}")
        print(f"  - 边数: {edge_count}")
        print(f"  - KillChain 数: {len(killchains)}")
        if killchains:
            print(f"  - 最高可信度: {max(kc.confidence for kc in killchains):.2f}")
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        graph_db.close()


if __name__ == "__main__":
    main()
