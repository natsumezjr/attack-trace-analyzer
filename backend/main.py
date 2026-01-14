from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging
from app.services.online_targets import start_polling, stop_polling

configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # 应用启动时开启轮询
    await start_polling()
    try:
        yield
    finally:
        # 应用关闭时停止轮询
        await stop_polling()


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
app.include_router(api_router)
