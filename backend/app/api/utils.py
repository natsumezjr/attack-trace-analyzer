from __future__ import annotations

from datetime import datetime

from app.core.time import format_rfc3339, utc_now as core_utc_now


def utc_now() -> datetime:
    return core_utc_now()


def utc_now_rfc3339() -> str:
    # Go client uses time.RFC3339Nano; Python only supports microseconds.
    return format_rfc3339(utc_now(), timespec="microseconds")


def ok(**data: object) -> dict[str, object]:
    return {"status": "ok", **data}


def err(code: str, message: str) -> dict[str, object]:
    return {
        "status": "error",
        "error": {
            "code": code,
            "message": message,
        },
    }
