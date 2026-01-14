import sys

from pathlib import Path

# Prefer package-relative imports (`python -m app.services.neo4j.load`), but keep a
# fallback path injection so `python backend/app/services/neo4j/load.py` still works.
GRAPH_DIR = Path(__file__).resolve().parent
SERVICES_DIR = GRAPH_DIR.parent
try:
    from . import db as graph_api
    from . import ingest
except ImportError:  # pragma: no cover
    if str(SERVICES_DIR) not in sys.path:
        sys.path.insert(0, str(SERVICES_DIR))
    from neo4j import api as graph_api  # type: ignore


def main() -> None:
    total_events, node_count, edge_count = graph_api.ingest_from_opensearch()

    alarm_edges = graph_api.get_alarm_edges()
    print(f"Loaded {total_events} events.")
    print(f"Inserted {node_count} nodes, {edge_count} edges.")
    print(f"Alarm edges: {len(alarm_edges)}")
    graph_api.close()


if __name__ == "__main__":
    main()
