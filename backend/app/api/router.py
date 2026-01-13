from fastapi import APIRouter

from app.api.routes import health, root

api_router = APIRouter()
api_router.include_router(root.router, tags=["root"])
api_router.include_router(health.router, tags=["health"])
