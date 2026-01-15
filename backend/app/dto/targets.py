from pydantic import BaseModel, Field, IPvAnyAddress


class RegisterTargetRequest(BaseModel):
    ip: IPvAnyAddress = Field(..., description="target IP")
