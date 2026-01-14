from __future__ import annotations

from datetime import datetime, timezone

from app.services.neo4j.utils import _parse_ts_to_float


def test_parse_ts_to_float_none_or_empty() -> None:
    assert _parse_ts_to_float(None) == 0.0
    assert _parse_ts_to_float("") == 0.0


def test_parse_ts_to_float_numeric_string() -> None:
    assert _parse_ts_to_float("1698400800.0") == 1698400800.0


def test_parse_ts_to_float_iso_with_z_suffix() -> None:
    expected = datetime(2023, 10, 27, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    assert _parse_ts_to_float("2023-10-27T10:00:00Z") == expected


def test_parse_ts_to_float_iso_with_offset() -> None:
    expected = datetime(2023, 10, 27, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    assert _parse_ts_to_float("2023-10-27T10:00:00+00:00") == expected


def test_parse_ts_to_float_invalid_returns_zero() -> None:
    assert _parse_ts_to_float("not-a-timestamp") == 0.0

