#!/usr/bin/env python3
"""
导入测试数据到 Neo4j 数据库

从 backend/tests/fixtures/graph/testExample.json 读取 ECS 事件数据，
并导入到 Neo4j 图数据库中。

用法:
    python scripts/import_test_data.py
    或
    docker compose exec python python scripts/import_test_data.py
"""

import json
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.neo4j import db as graph_db
from app.services.neo4j import ingest as graph_ingest


def load_test_events() -> list[dict]:
    """从 testExample.json 加载测试事件"""
    fixture_path = backend_dir / "tests" / "fixtures" / "graph" / "testExample.json"
    
    if not fixture_path.exists():
        raise FileNotFoundError(f"测试数据文件不存在: {fixture_path}")
    
    print(f"正在读取测试数据: {fixture_path}")
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        raise ValueError(f"测试数据格式错误: 期望 list，得到 {type(data)}")
    
    print(f"成功加载 {len(data)} 条事件")
    return data


def get_alarm_edges_count() -> int:
    """获取告警边数量"""
    try:
        alarm_edges = graph_db.get_alarm_edges()
        return len(alarm_edges)
    except Exception as e:
        print(f"警告: 无法获取告警边数量: {e}")
        return 0


def main():
    """主函数"""
    print("=" * 60)
    print("Neo4j 测试数据导入")
    print("=" * 60)
    
    try:
        # 1. 初始化 Neo4j schema
        print("\n[1/3] 初始化 Neo4j schema...")
        graph_db.ensure_schema()
        print("✓ Schema 初始化完成")
        
        # 2. 加载测试数据
        print("\n[2/3] 加载测试数据...")
        events = load_test_events()
        
        # 3. 导入数据
        print("\n[3/3] 导入数据到 Neo4j...")
        node_count, edge_count = graph_ingest.ingest_ecs_events(events)
        print(f"✓ 导入完成: {node_count} 个节点, {edge_count} 条边")
        
        # 4. 获取告警边统计
        print("\n[统计] 查询告警边...")
        alarm_count = get_alarm_edges_count()
        print(f"✓ 告警边数量: {alarm_count}")
        
        print("\n" + "=" * 60)
        print("导入完成！")
        print("=" * 60)
        print(f"\n统计信息:")
        print(f"  - 事件数: {len(events)}")
        print(f"  - 节点数: {node_count}")
        print(f"  - 边数: {edge_count}")
        print(f"  - 告警边数: {alarm_count}")
        print(f"\n可以在 Neo4j 浏览器 (http://localhost:7474) 中查看数据")
        
    except Exception as e:
        print(f"\n❌ 导入失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # 关闭数据库连接
        graph_db.close()


if __name__ == "__main__":
    main()
