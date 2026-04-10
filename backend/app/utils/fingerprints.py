"""
Entity fingerprint generation for deduplication.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_entity_fingerprint(
    source_type: str,
    event_name: str,
    source_ip: str | None,
    user_name: str | None,
    host_name: str | None,
    event_time_str: str,
    extra_keys: dict[str, Any] | None = None,
) -> str:
    """
    Compute a SHA-256 fingerprint for an alert.

    Used to detect exact duplicates. Two alerts with the same fingerprint
    are considered the same event from the same source.
    """
    components = [
        source_type or "",
        event_name or "",
        source_ip or "",
        user_name or "",
        host_name or "",
        event_time_str or "",
    ]

    if extra_keys:
        # Sort keys for deterministic output
        for key in sorted(extra_keys.keys()):
            val = extra_keys[key]
            if val is not None:
                components.append(f"{key}={val}")

    fingerprint_input = "|".join(components)
    return hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()
