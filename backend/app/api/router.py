from fastapi import APIRouter

from app.api.routes import analysis_tasks, clients, events, findings, graph, health, root, targets
from app.services.analyze.ttp_similarity.router import router as ttp_similarity_router

api_router = APIRouter()
api_router.include_router(root.router, tags=["root"])
api_router.include_router(health.router, tags=["health"])
api_router.include_router(events.router, tags=["events"])
api_router.include_router(findings.router, tags=["findings"])
api_router.include_router(graph.router, tags=["graph"])
api_router.include_router(targets.router, tags=["targets"])
api_router.include_router(clients.router, tags=["clients"])
api_router.include_router(analysis_tasks.router, tags=["analysis"])
api_router.include_router(ttp_similarity_router, tags=["analysis"])
