from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_rfc3339() -> str:
    # Go client uses time.RFC3339Nano; Python only supports microseconds.
    return utc_now().isoformat(timespec="microseconds").replace("+00:00", "Z")


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

