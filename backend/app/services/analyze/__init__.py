"""
Analysis algorithms (task-driven).

This package is the single home for all analysis/algorithm implementations.
It is designed to be driven by a `task_id` and write results back to:
  - OpenSearch task document (analysis-tasks-*)
  - Neo4j edge properties (analysis.*)
"""

from app.services.analyze.pipeline import new_task_id, run_analysis_task

# Legacy / algorithm-level exports (still useful for local debugging / scripts).
from app.services.analyze.killchain import KillChain, run_killchain_pipeline

__all__ = [
    "new_task_id",
    "run_analysis_task",
    "KillChain",
    "run_killchain_pipeline",
]
