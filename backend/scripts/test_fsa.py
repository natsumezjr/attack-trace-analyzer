#!/usr/bin/env python3
"""
FSA 状态机测试脚本

专门用于测试 FSA 状态机的功能，不依赖完整的 killchain 分析流程。
测试流程：
1. 导入测试数据到 Neo4j
2. 获取告警边
3. 运行 FSA 状态机
4. 输出结果分析

用法:
    python scripts/test_fsa.py
    或
    docker compose exec python python scripts/test_fsa.py
"""

import json
import sys
from pathlib import Path
from typing import List

# 添加项目根目录到 Python 路径
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.neo4j import db as graph_db
from app.services.neo4j import ingest as graph_ingest
from app.services.analyze.attack_fsa import behavior_state_machine, AttackState, FSAGraph


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


def print_fsa_graph_summary(graphs: List[FSAGraph]) -> None:
    """打印 FSA 图摘要"""
    print("\n" + "=" * 60)
    print("FSA 状态机分析结果")
    print("=" * 60)
    
    if not graphs:
        print("❌ 未生成任何 FSA 图")
        return
    
    print(f"✓ 生成了 {len(graphs)} 个 FSA 图\n")
    
    for i, graph in enumerate(graphs, 1):
        print(f"--- FSA Graph #{i} ---")
        print(f"节点数: {len(graph.nodes)}")
        
        # 提取状态序列
        states = []
        for node in graph.nodes:
            if hasattr(node, 'state') and node.state:
                states.append(node.state.value)
        
        if states:
            print(f"状态序列: {' -> '.join(states)}")
        else:
            print("状态序列: (无状态)")
        
        # 显示 trace 信息（如果有）
        if hasattr(graph, 'trace') and graph.trace:
            print(f"Trace 长度: {len(graph.trace)}")
            if len(graph.trace) <= 5:
                for trace_item in graph.trace:
                    print(f"  - {trace_item}")
        
        print()


def analyze_fsa_results(graphs: List[FSAGraph]) -> None:
    """分析 FSA 结果，验证是否正确识别了攻击链"""
    print("\n" + "=" * 60)
    print("FSA 结果验证")
    print("=" * 60)
    
    expected_states = [
        AttackState.INITIAL_ACCESS.value,
        AttackState.EXECUTION.value,
        AttackState.PRIVILEGE_ESCALATION.value,
        AttackState.LATERAL_MOVEMENT.value,
        AttackState.COMMAND_AND_CONTROL.value,
        AttackState.IMPACT.value,
    ]
    
    found_correct_chain = False
    
    for i, graph in enumerate(graphs, 1):
        states = []
        for node in graph.nodes:
            if hasattr(node, 'state') and node.state:
                states.append(node.state.value)
        
        # 检查是否包含完整的攻击链
        if all(state in states for state in expected_states):
            # 检查顺序是否正确（允许中间有其他状态）
            state_indices = [states.index(s) for s in expected_states if s in states]
            if state_indices == sorted(state_indices):
                print(f"✅ FSA Graph #{i}: 包含完整且顺序正确的攻击链")
                found_correct_chain = True
            else:
                print(f"⚠️  FSA Graph #{i}: 包含所有状态但顺序可能不正确")
        else:
            missing = [s for s in expected_states if s not in states]
            print(f"⚠️  FSA Graph #{i}: 缺少状态 {missing}")
    
    if not found_correct_chain:
        print("\n❌ 未找到完整且顺序正确的攻击链")
    else:
        print("\n✅ 测试通过：FSA 状态机正确识别了攻击链")


def main():
    """主函数"""
    print("=" * 60)
    print("FSA 状态机测试")
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
        
        # 5. 获取告警边并运行 FSA
        print("\n[5/5] 运行 FSA 状态机...")
        alarm_edges = graph_db.get_alarm_edges()
        print(f"✓ 获取到 {len(alarm_edges)} 条告警边")
        
        if not alarm_edges:
            print("⚠️  警告: 没有告警边，无法运行 FSA 状态机")
            print("   请检查测试数据中是否包含 threat.tactic.name 字段")
            return
        
        print("正在运行 FSA 状态机...")
        fsa_graphs = behavior_state_machine(alarm_edges)
        
        # 6. 输出结果
        print_fsa_graph_summary(fsa_graphs)
        analyze_fsa_results(fsa_graphs)
        
        print("\n" + "=" * 60)
        print("测试完成！")
        print("=" * 60)
        print(f"\n统计信息:")
        print(f"  - 事件数: {len(events)}")
        print(f"  - 节点数: {node_count}")
        print(f"  - 边数: {edge_count}")
        print(f"  - 告警边数: {len(alarm_edges)}")
        print(f"  - FSA 图数: {len(fsa_graphs)}")
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        graph_db.close()




if __name__ == "__main__":
    main()
