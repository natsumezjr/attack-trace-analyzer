from datetime import datetime, timedelta, timezone
import sys

from pathlib import Path

# Prefer package-relative imports (`python -m app.services.neo4j.load`), but keep a
# fallback path injection so `python backend/app/services/neo4j/load.py` still works.
GRAPH_DIR = Path(__file__).resolve().parent
SERVICES_DIR = GRAPH_DIR.parent
try:
    from . import db as graph_db
    from .ingest import ingest_from_opensearch_ingested_window
except ImportError:  # pragma: no cover
    if str(SERVICES_DIR) not in sys.path:
        sys.path.insert(0, str(SERVICES_DIR))
    from neo4j import db as graph_db  # type: ignore
    from neo4j.ingest import ingest_from_opensearch_ingested_window  # type: ignore


def main() -> None:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    total_events, node_count, edge_count = ingest_from_opensearch_ingested_window(
        start_time=start,
        end_time=now,
        size=10000,
        include_events=True,
        include_canonical_findings=True,
    )

    alarm_edges = graph_db.get_alarm_edges()
    print(f"Loaded {total_events} events.")
    print(f"Inserted {node_count} nodes, {edge_count} edges.")
    print(f"Alarm edges: {len(alarm_edges)}")
    graph_db.close()


if __name__ == "__main__":
    main()
