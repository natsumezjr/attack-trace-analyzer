from pathlib import Path
import json
import sys

GRAPH_DIR = Path(__file__).resolve().parent
SERVICES_DIR = GRAPH_DIR.parent
APP_DIR = SERVICES_DIR.parent
BACKEND_DIR = APP_DIR.parent

# Prefer package-relative imports (`python -m app.services.neo4j.load`), but keep a
# fallback path injection so `python backend/app/services/neo4j/load.py` still works.
try:
    from . import api as graph_api
except ImportError:  # pragma: no cover
    if str(SERVICES_DIR) not in sys.path:
        sys.path.insert(0, str(SERVICES_DIR))
    from neo4j import api as graph_api  # type: ignore

# 样例文件优先从测试夹读取，旧路径仅作兼容兜底
SAMPLE_EVENTS_PATH = BACKEND_DIR / "tests" / "fixtures" / "graph" / "testExample.json"
LEGACY_SAMPLE_EVENTS_PATH = SERVICES_DIR / "graph" / "testExample.json"


def main() -> None:
    if "--file" in sys.argv:
        # 本地样例入图：不依赖 OpenSearch
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
        # 通过 OpenSearch 拉取并入图
        total_events, node_count, edge_count = graph_api.ingest_from_opensearch()
    alarm_edges = graph_api.get_alarm_edges()
    print(f"Loaded {total_events} events.")
    print(f"Inserted {node_count} nodes, {edge_count} edges.")
    print(f"Alarm edges: {len(alarm_edges)}")
    graph_api.close()


if __name__ == "__main__":
    main()
