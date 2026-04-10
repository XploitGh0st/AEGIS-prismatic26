"""
NormalizedAlert schemas — response models for canonical alerts.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class NormalizedAlertResponse(BaseModel):
    """Canonical alert output for API responses."""

    id: str
    raw_alert_id: str
    source_family: str
    source_type: str
    event_time: datetime
    category: str
    event_name: str
    severity: str
    confidence: float

    # Entity fields
    user_name: str | None = None
    host_name: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None

    # MITRE
    mitre_technique_ids: list[str] | None = None
    mitre_tactic: str | None = None

    # Context
    description: str | None = None
    risk_flags: list[str] | None = None
    raw_command: str | None = None
    session_id: str | None = None
    extra_data: dict | None = None

    entity_fingerprint: str
    normalized_at: datetime

    model_config = {"from_attributes": True}


class NormalizedAlertListResponse(BaseModel):
    """Paginated list of normalized alerts."""

    total: int
    page: int
    page_size: int
    alerts: list[NormalizedAlertResponse]
