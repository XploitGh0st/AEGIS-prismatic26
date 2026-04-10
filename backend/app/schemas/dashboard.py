"""
Dashboard schemas — response models for KPI metrics and chart data.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DashboardKPI(BaseModel):
    """Single KPI card."""

    label: str
    value: int | float
    change: float | None = None  # vs previous period
    trend: str | None = None  # up, down, flat


class DashboardOverview(BaseModel):
    """Dashboard overview — top-level KPI metrics."""

    total_alerts_ingested: DashboardKPI
    open_incidents: DashboardKPI
    critical_incidents: DashboardKPI
    avg_alerts_per_incident: DashboardKPI
    mean_time_to_detect_seconds: DashboardKPI | None = None


class SeverityDistribution(BaseModel):
    """Severity distribution chart data."""

    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class SourceDistribution(BaseModel):
    """Alert count by source family."""

    source: str
    count: int


class TimelinePoint(BaseModel):
    """Point on a time-series chart."""

    timestamp: datetime
    count: int
    label: str | None = None


class RecentAlert(BaseModel):
    """Recent alert for live feed."""

    id: str
    event_name: str
    severity: str
    source_ip: str | None = None
    user_name: str | None = None
    event_time: datetime
    source_family: str


class DashboardCharts(BaseModel):
    """Dashboard chart data bundle."""

    severity_distribution: SeverityDistribution
    alerts_by_source: list[SourceDistribution]
    alerts_timeline: list[TimelinePoint] = Field(default_factory=list)
    recent_alerts: list[RecentAlert] = Field(default_factory=list)
    recent_incidents: list[dict] = Field(default_factory=list)
