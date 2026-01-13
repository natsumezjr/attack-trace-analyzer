from pathlib import Path
import json
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from graph import api as graph_api


def main() -> None:
    # 使用 testExample.json 进行模块测试
    data = json.loads((ROOT_DIR / "graph" / "testExample.json").read_text(encoding="utf-8"))
    events = data.get("events", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    node_count, edge_count = graph_api.ingest_ecs_events(events)
    alarm_edges = graph_api.get_alarm_edges()
    print(f"Loaded {len(events)} events.")
    print(f"Inserted {node_count} nodes, {edge_count} edges.")
    print(f"Alarm edges: {len(alarm_edges)}")
    graph_api.close()


if __name__ == "__main__":
    main()
