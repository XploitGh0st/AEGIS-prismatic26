"""
Incident schemas — response models for incidents.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.normalized_alert import NormalizedAlertResponse


class CorrelationMatchResponse(BaseModel):
    """Correlation reason code for an alert-incident attachment."""

    total_score: int
    reason_codes: dict
    matched_entity: str | None = None
    match_type: str

    model_config = {"from_attributes": True}


class IncidentSummaryResponse(BaseModel):
    """AI / deterministic summary for an incident."""

    id: str
    version: int
    generation_type: str
    executive_summary: str
    root_cause: str | None = None
    observed_facts: list | None = None
    recommended_actions: list | None = None
    confidence_notes: str | None = None
    model_used: str | None = None
    generation_time_ms: int | None = None
    validation_passed: bool | None = None
    generated_at: datetime

    model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
    """Incident list response — summary view."""

    id: str
    incident_number: str
    title: str
    classification: str
    severity: str
    severity_score: int
    confidence: float
    status: str
    primary_user: str | None = None
    primary_host: str | None = None
    primary_src_ip: str | None = None
    alert_count: int
    mitre_techniques: list[str] | None = None
    source_families: list[str] | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class IncidentDetailResponse(IncidentResponse):
    """Incident detail — full view with alerts, summaries, correlations."""

    primary_dst_ip: str | None = None
    mitre_tactics: list[str] | None = None
    scoring_breakdown: dict | None = None
    updated_at: datetime

    # Nested details
    alerts: list[NormalizedAlertResponse] = Field(default_factory=list)
    summaries: list[IncidentSummaryResponse] = Field(default_factory=list)
    correlation_matches: list[CorrelationMatchResponse] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    """Paginated list of incidents."""

    total: int
    page: int
    page_size: int
    incidents: list[IncidentResponse]


class IncidentStatusUpdate(BaseModel):
    """Request to update incident status."""

    status: str = Field(
        ...,
        pattern=r"^(new|in_progress|resolved|false_positive|closed)$",
        description="New status for the incident",
    )
    reason: str | None = Field(None, description="Reason for the status change")
