from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging
from app.services.analyze.runner import start_task_runner, stop_task_runner
from app.services.client_poller import start_polling, stop_polling
from app.services.opensearch.index import initialize_indices

configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # OpenSearch 索引必须在任何轮询/分析任务运行前存在
    initialize_indices()
    # 应用启动时开启轮询
    await start_polling()
    await start_task_runner()
    try:
        yield
    finally:
        # 应用关闭时停止轮询
        await stop_task_runner()
        await stop_polling()


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
app.include_router(api_router)
