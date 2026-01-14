from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.api.routes import chains, events, findings, graph, health, root, targets
from app.api.utils import err

try:
    from app.services.ttp_similarity.router import router as ttp_similarity_router
except Exception as error:
    # Do not block the entire API service if optional analysis modules are broken
    # or their dependencies are unavailable. Expose a clear 501 instead.
    _ttp_similarity_import_error = str(error)
    ttp_similarity_router = APIRouter()

    @ttp_similarity_router.post("/api/v1/analysis/ttp-similarity")
    def ttp_similarity_unavailable():
        return JSONResponse(
            status_code=501,
            content=err(
                "NOT_IMPLEMENTED",
                f"ttp similarity unavailable: {_ttp_similarity_import_error}",
            ),
        )

api_router = APIRouter()
api_router.include_router(root.router, tags=["root"])
api_router.include_router(health.router, tags=["health"])
api_router.include_router(events.router, tags=["events"])
api_router.include_router(findings.router, tags=["findings"])
api_router.include_router(graph.router, tags=["graph"])
api_router.include_router(chains.router, tags=["chains"])
api_router.include_router(targets.router, tags=["targets"])
api_router.include_router(ttp_similarity_router, tags=["analysis"])
