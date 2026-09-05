"""Strict UTC timestamp handling."""

from __future__ import annotations

import re
from datetime import UTC, datetime

RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not RFC3339_UTC.fullmatch(value):
        raise ValueError("timestamp must be RFC 3339 UTC with a trailing Z")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC:
        raise ValueError("timestamp must use UTC")
    return parsed


def format_time(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def utc_now() -> datetime:
    return datetime.now(UTC)
