#!/usr/bin/env python3
"""
测试 analyze_killchain 功能（结合大模型）

调用 analyze_killchain 接口对数据库中的测试数据进行分析，
并输出结果和 Neo4j 查询示例。
使用 testFSA.json 作为测试数据，会自动清空数据库并重新导入。

用法:
    python scripts/test_analyze.py
    或
    docker compose exec python python scripts/test_analyze.py
"""

import json
import sys
import uuid
from pathlib import Path
from typing import List

# 添加项目根目录到 Python 路径
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.analyze import analyze_killchain
from app.services.analyze.attack_fsa import AttackState
from app.services.analyze.killchain import KillChain
from app.services.neo4j import db as graph_db
from app.services.neo4j import ingest as graph_ingest


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
    import os
    import json
    from datetime import datetime
    
    # #region agent log
    backend_dir = Path(__file__).resolve().parent.parent
    log_path = str(backend_dir.parent / ".cursor" / "debug.log")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": datetime.now().isoformat(),
                "location": "test_analyze.py:delete_existing_test_data",
                "message": "开始清理测试数据",
                "data": {"event_count": len(events)},
                "sessionId": "debug-session",
                "runId": "run1",
                "hypothesisId": "A"
            }, ensure_ascii=False) + "\n")
    except:
        pass
    # #endregion
    
    event_ids = [e.get("event", {}).get("id") for e in events if e.get("event", {}).get("id")]
    host_ids = set()
    user_ids = set()
    domain_names = set()
    ip_addresses = set()
    
    for event in events:
        host_id = event.get("host", {}).get("id")
        if host_id:
            host_ids.add(host_id)
        user_id = event.get("user", {}).get("id")
        if user_id:
            user_ids.add(user_id)
        # 提取域名
        dns = event.get("dns", {})
        if dns:
            question = dns.get("question", {})
            if question and question.get("name"):
                domain_names.add(question.get("name"))
        # 提取 IP 地址
        source_ip = event.get("source", {}).get("ip")
        if source_ip:
            ip_addresses.add(source_ip)
        dest_ip = event.get("destination", {}).get("ip")
        if dest_ip:
            ip_addresses.add(dest_ip)
        host_ips = event.get("host", {}).get("ip", [])
        if host_ips:
            ip_addresses.update(host_ips)
    
    # #region agent log
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": datetime.now().isoformat(),
                "location": "test_analyze.py:delete_existing_test_data",
                "message": "提取的清理目标",
                "data": {
                    "host_ids": list(host_ids),
                    "user_ids": list(user_ids),
                    "domain_names": list(domain_names),
                    "ip_addresses": list(ip_addresses),
                    "event_ids_count": len(event_ids)
                },
                "sessionId": "debug-session",
                "runId": "run1",
                "hypothesisId": "A"
            }, ensure_ascii=False) + "\n")
    except:
        pass
    # #endregion
    
    with graph_db._get_session() as session:
        # 清理旧的 killchain 分析结果（通过 analysis.task_id）
        result = session.run("""
            MATCH (n)
            WHERE n.`analysis.task_id` IS NOT NULL
            WITH DISTINCT n.`analysis.task_id` AS task_id
            MATCH (n)-[r]-(m)
            WHERE n.`analysis.task_id` = task_id OR r.`analysis.task_id` = task_id OR m.`analysis.task_id` = task_id
            DELETE r
            RETURN count(r) AS cnt
        """)
        count = result.single()["cnt"] if result.peek() else 0
        print(f"[清理] 删除了 {count} 条 killchain 分析边")
        
        result = session.run("""
            MATCH (n)
            WHERE n.`analysis.task_id` IS NOT NULL
            REMOVE n.`analysis.task_id`
            RETURN count(n) AS cnt
        """)
        count = result.single()["cnt"] if result.peek() else 0
        print(f"[清理] 移除了 {count} 个节点的 killchain 分析标记")
        
        if event_ids:
            result = session.run("MATCH ()-[r]->() WHERE r.`event.id` IN $ids DELETE r RETURN count(r) AS cnt", ids=event_ids)
            count = result.single()["cnt"] if result.peek() else 0
            print(f"[清理] 删除了 {count} 条边（通过 event.id）")
        if user_ids:
            result = session.run("MATCH (n:User) WHERE n.`user.id` IN $user_ids DETACH DELETE n RETURN count(n) AS cnt", user_ids=list(user_ids))
            count = result.single()["cnt"] if result.peek() else 0
            print(f"[清理] 删除了 {count} 个 User 节点")
        if host_ids:
            result = session.run("MATCH (n:Host) WHERE n.`host.id` IN $host_ids DETACH DELETE n RETURN count(n) AS cnt", host_ids=list(host_ids))
            count = result.single()["cnt"] if result.peek() else 0
            print(f"[清理] 删除了 {count} 个 Host 节点")
            result = session.run("MATCH (n:Process) WHERE n.`host.id` IN $host_ids DETACH DELETE n RETURN count(n) AS cnt", host_ids=list(host_ids))
            count = result.single()["cnt"] if result.peek() else 0
            print(f"[清理] 删除了 {count} 个 Process 节点")
            result = session.run("MATCH (n:File) WHERE n.`host.id` IN $host_ids DETACH DELETE n RETURN count(n) AS cnt", host_ids=list(host_ids))
            count = result.single()["cnt"] if result.peek() else 0
            print(f"[清理] 删除了 {count} 个 File 节点")
        if domain_names:
            result = session.run("MATCH (n:Domain) WHERE n.`domain.name` IN $domain_names DETACH DELETE n RETURN count(n) AS cnt", domain_names=list(domain_names))
            count = result.single()["cnt"] if result.peek() else 0
            print(f"[清理] 删除了 {count} 个 Domain 节点")
        if ip_addresses:
            result = session.run("MATCH (n:IP) WHERE n.`ip` IN $ip_addresses DETACH DELETE n RETURN count(n) AS cnt", ip_addresses=list(ip_addresses))
            count = result.single()["cnt"] if result.peek() else 0
            print(f"[清理] 删除了 {count} 个 IP 节点")
        
        # 验证清理结果：检查是否还有旧数据残留
        # #region agent log
        try:
            # 检查是否还有包含旧语义的域名
            result = session.run("""
                MATCH (n:Domain)
                WHERE n.`domain.name` CONTAINS 'evil' OR n.`domain.name` CONTAINS 'c2' OR n.`domain.name` CONTAINS 'malicious'
                RETURN n.`domain.name` AS domain_name
                LIMIT 10
            """)
            old_domains = [record["domain_name"] for record in result]
            
            # 检查是否还有包含旧语义的主机名
            result = session.run("""
                MATCH (n:Host)
                WHERE n.`host.name` CONTAINS 'victim' OR n.`host.name` CONTAINS 'malicious'
                RETURN n.`host.name` AS host_name
                LIMIT 10
            """)
            old_hosts = [record["host_name"] for record in result]
            
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "timestamp": datetime.now().isoformat(),
                    "location": "test_analyze.py:delete_existing_test_data",
                    "message": "清理后验证：检查旧数据残留",
                    "data": {
                        "old_domains_found": old_domains,
                        "old_hosts_found": old_hosts
                    },
                    "sessionId": "debug-session",
                    "runId": "run1",
                    "hypothesisId": "A"
                }, ensure_ascii=False) + "\n")
        except Exception as e:
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "timestamp": datetime.now().isoformat(),
                        "location": "test_analyze.py:delete_existing_test_data",
                        "message": "清理后验证失败",
                        "data": {"error": str(e)},
                        "sessionId": "debug-session",
                        "runId": "run1",
                        "hypothesisId": "A"
                    }, ensure_ascii=False) + "\n")
            except:
                pass
        # #endregion


def print_killchain_summary(killchains: List[KillChain]) -> None:
    """打印 killchain 摘要信息"""
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
        print(f"解释: {kc.explanation}" if kc.explanation else "解释: (无)")
        
        # 显示状态序列
        if kc.segments:
            states = [seg.state for seg in kc.segments]
            print(f"状态序列: {' -> '.join(states)}")
        
        # 显示选中的路径
        if kc.selected_paths:
            print(f"\n选中的路径:")
            for j, path in enumerate(kc.selected_paths, 1):
                print(f"  Path #{j}: {path.path_id}")
                print(f"    - 源锚点: {path.src_anchor}")
                print(f"    - 目标锚点: {path.dst_anchor}")
                print(f"    - 边数: {len(path.edges)}")
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
        
        states = [seg.state for seg in kc.segments]
        
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
    print("KillChain 分析测试（结合大模型）")
    print("=" * 60)
    
    try:
        # 1. 初始化 Neo4j schema
        print("\n[1/6] 初始化 Neo4j schema...")
        graph_db.ensure_schema()
        print("✓ Schema 初始化完成")
        
        # 2. 加载测试数据
        print("\n[2/6] 加载测试数据...")
        events = load_test_events()
        
        # 3. 清理旧数据
        print("\n[3/6] 清理旧测试数据...")
        delete_existing_test_data(events)
        print("✓ 清理完成")
        
        # 4. 导入数据
        print("\n[4/6] 导入数据到 Neo4j...")
        node_count, edge_count = graph_ingest.ingest_ecs_events(events)
        print(f"✓ 导入完成: {node_count} 个节点, {edge_count} 条边")
        
        # 5. 生成 killchain UUID
        print("\n[5/6] 生成 killchain UUID...")
        kc_uuid = str(uuid.uuid4())
        print(f"✓ KillChain UUID: {kc_uuid}")
        
        # 6. 运行分析（使用大模型）
        print("\n[6/6] 运行 killchain 分析（结合大模型）...")
        print("这可能需要一些时间，请耐心等待...\n")
        
        killchains = analyze_killchain(kc_uuid)
        
        print(f"\n✓ 分析完成！生成了 {len(killchains)} 个 killchain")
        
        # 7. 输出结果摘要
        print_killchain_summary(killchains)
        analyze_killchain_results(killchains)
        
        # 8. 显示 Neo4j 查询示例
        kc_uuids = [kc.kc_uuid for kc in killchains]
        if kc_uuids:
            best_kc = max(killchains, key=lambda kc: kc.confidence)
            print("\n" + "=" * 60)
            print("Neo4j 浏览器查询示例")
            print("=" * 60)
            print(f"\n访问 Neo4j 浏览器: http://localhost:7474")
            print(f"\n查询所有 killchain UUID:")
            print("-" * 60)
            print("""MATCH (n)
WHERE n.`analysis.task_id` IS NOT NULL
RETURN DISTINCT n.`analysis.task_id` AS kc_uuid
ORDER BY kc_uuid""")
            
            print(f"\n查询最高可信度的 KillChain (UUID: {best_kc.kc_uuid}, 可信度: {best_kc.confidence:.2f}):")
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
        # 关闭数据库连接
        graph_db.close()


if __name__ == "__main__":
    main()
