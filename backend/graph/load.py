from pathlib import Path
import json
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from graph import api as graph_api


def main() -> None:
    # 读取样例事件并写入 Neo4j，输出统计信息
    # 使用 OpenSearch API 拉取 ECS 事件并写入 Neo4j
    if "--file" in sys.argv:
        data = json.loads((ROOT_DIR / "graph" / "testExample.json").read_text(encoding="utf-8"))
        if isinstance(data, dict):
            events = data.get("events", [])
        elif isinstance(data, list):
            events = data
        else:
            events = []
        total_events = len(events)
        node_count, edge_count = graph_api.ingest_ecs_events(events)
    else:
        total_events, node_count, edge_count = graph_api.ingest_from_opensearch()
    alarm_edges = graph_api.get_alarm_edges()
    print(f"Loaded {total_events} events.")
    print(f"Inserted {node_count} nodes, {edge_count} edges.")
    print(f"Alarm edges: {len(alarm_edges)}")
    graph_api.close()


if __name__ == "__main__":
    main()
