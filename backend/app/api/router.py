from fastapi import APIRouter

from app.api.routes import health, root, ttp_similarity

api_router = APIRouter()
api_router.include_router(root.router, tags=["root"])
api_router.include_router(health.router, tags=["health"])
api_router.include_router(ttp_similarity.router, tags=["analysis"])
