"""
Alert Ingest schemas — request validation for incoming alerts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AlertIngestRequest(BaseModel):
    """Single alert ingest payload — validates POST /api/v1/alerts/ingest."""

    source_family: str = Field(
        ...,
        description="Origin family: siem, edr, ids, honeypot",
        examples=["siem"],
        pattern=r"^(siem|edr|ids|honeypot)$",
    )
    source_type: str = Field(
        ...,
        description="Specific source: splunk_mock, crowdstrike_mock, cowrie_splunk, suricata_mock",
        examples=["cowrie_splunk"],
    )
    external_alert_id: str | None = Field(
        None,
        description="Dedup key from originating system",
        max_length=255,
    )
    event_time: datetime = Field(
        ...,
        description="When the event actually occurred (ISO 8601)",
    )
    payload: dict[str, Any] = Field(
        ...,
        description="Full raw event payload from the source",
    )

    @field_validator("source_type")
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        valid_types = {
            "splunk_mock", "crowdstrike_mock", "suricata_mock",
            "cowrie_splunk", "cowrie_direct",
            "generic_siem", "generic_edr", "generic_ids",
        }
        if v not in valid_types:
            # Allow unknown types but normalize
            pass
        return v.lower()


class AlertBulkIngestRequest(BaseModel):
    """Bulk ingest — validates POST /api/v1/alerts/bulk."""

    alerts: list[AlertIngestRequest] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="List of alerts to ingest (max 500 per batch)",
    )


class AlertIngestResponse(BaseModel):
    """Response after successful ingest."""

    raw_alert_id: str
    status: str = "accepted"
    message: str = "Alert queued for normalization"


class AlertBulkIngestResponse(BaseModel):
    """Response after bulk ingest."""

    accepted: int
    rejected: int = 0
    alerts: list[AlertIngestResponse]
    errors: list[dict[str, Any]] = Field(default_factory=list)
