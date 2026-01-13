from pathlib import Path
import json
import sys

SERVICES_DIR = Path(__file__).resolve().parents[1]

# Prefer package-relative imports (`python -m app.services.graph.load`), but keep a
# fallback path injection so `python backend/app/services/graph/load.py` still works.
try:
    from . import api as graph_api
except ImportError:  # pragma: no cover
    if str(SERVICES_DIR) not in sys.path:
        sys.path.insert(0, str(SERVICES_DIR))
    from graph import api as graph_api  # type: ignore

SAMPLE_EVENTS_PATH = SERVICES_DIR / "tests" / "fixtures" / "graph" / "testExample.json"
LEGACY_SAMPLE_EVENTS_PATH = SERVICES_DIR / "graph" / "testExample.json"


def main() -> None:
    # 读取样例事件并写入 Neo4j，输出统计信息
    # 使用 OpenSearch API 拉取 ECS 事件并写入 Neo4j
    if "--file" in sys.argv:
        sample_path = SAMPLE_EVENTS_PATH if SAMPLE_EVENTS_PATH.exists() else LEGACY_SAMPLE_EVENTS_PATH
        data = json.loads(sample_path.read_text(encoding="utf-8"))
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
