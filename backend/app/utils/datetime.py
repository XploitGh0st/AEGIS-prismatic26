"""
Datetime utilities for AEGIS.
"""

from __future__ import annotations

from datetime import datetime, timezone

from dateutil.parser import isoparse


def parse_iso(value: str | datetime) -> datetime:
    """Parse an ISO 8601 string to a timezone-aware datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    dt = isoparse(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def time_diff_seconds(t1: datetime, t2: datetime) -> float:
    """Return the absolute difference in seconds between two datetimes."""
    return abs((t1 - t2).total_seconds())


def format_incident_number(date: datetime, sequence: int) -> str:
    """Generate a human-readable incident number: INC-YYYYMMDD-NNNN."""
    return f"INC-{date.strftime('%Y%m%d')}-{sequence:04d}"
