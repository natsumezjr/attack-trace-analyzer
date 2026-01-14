from fastapi import APIRouter

from app.api.utils import ok
from app.dto.targets import RegisterTargetRequest
from app.services.online_targets import register_target
from app.services.online_targets.registry import list_targets


router = APIRouter()


@router.post("/api/v1/targets/register")
def register_online_target(req: RegisterTargetRequest):
    # 注册在线靶机到内存表
    ip_str = str(req.ip)
    register_target(ip_str)
    return ok(ip=ip_str)


@router.get("/api/v1/targets")
def list_online_targets():
    # 列出所有在线靶机
    return ok(targets=list_targets())
