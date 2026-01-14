from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_rfc3339(dt: datetime, *, timespec: str = "microseconds") -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        if float(value) > 1e12:
            return datetime.fromtimestamp(float(value) / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None

        try:
            raw_num = float(s)
        except ValueError:
            raw_num = None

        if raw_num is not None:
            return parse_datetime(raw_num)

        if s.endswith("Z"):
            s = s[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    return None


def to_rfc3339(value: Any) -> str | None:
    dt = parse_datetime(value)
    if dt is None:
        return None
    return format_rfc3339(dt)


def utc_now_rfc3339() -> str:
    return format_rfc3339(utc_now())

