from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging

configure_logging(settings.log_level)

app = FastAPI(title=settings.app_name, version=settings.app_version)
app.include_router(api_router)
