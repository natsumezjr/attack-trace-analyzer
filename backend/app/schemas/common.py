from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class APIError(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    status: Literal["error"] = "error"
    error: APIError

