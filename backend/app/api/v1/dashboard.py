"""
Dashboard API — KPI metrics and chart data for the frontend.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.models.incident import Incident
from app.models.normalized_alert import NormalizedAlert
from app.models.raw_alert import RawAlert
from app.schemas.dashboard import (
    DashboardCharts,
    DashboardKPI,
    DashboardOverview,
    RecentAlert,
    SeverityDistribution,
    SourceDistribution,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=DashboardOverview)
async def dashboard_overview(
    session: AsyncSession = Depends(get_db_session),
):
    """Get dashboard overview KPI metrics."""
    # Total alerts ingested
    total_alerts = (
        await session.execute(select(func.count(RawAlert.id)))
    ).scalar() or 0

    # Open incidents
    open_incidents = (
        await session.execute(
            select(func.count(Incident.id)).where(
                Incident.status.in_(["new", "in_progress"])
            )
        )
    ).scalar() or 0

    # Critical incidents
    critical_incidents = (
        await session.execute(
            select(func.count(Incident.id)).where(
                Incident.severity == "critical",
                Incident.status.in_(["new", "in_progress"]),
            )
        )
    ).scalar() or 0

    # Average alerts per incident
    total_incidents = (
        await session.execute(select(func.count(Incident.id)))
    ).scalar() or 0

    avg_alerts = round(total_alerts / max(total_incidents, 1), 1)

    return DashboardOverview(
        total_alerts_ingested=DashboardKPI(
            label="Alerts Ingested", value=total_alerts
        ),
        open_incidents=DashboardKPI(
            label="Open Incidents", value=open_incidents
        ),
        critical_incidents=DashboardKPI(
            label="Critical Incidents", value=critical_incidents
        ),
        avg_alerts_per_incident=DashboardKPI(
            label="Avg Alerts/Incident", value=avg_alerts
        ),
    )


@router.get("/charts", response_model=DashboardCharts)
async def dashboard_charts(
    session: AsyncSession = Depends(get_db_session),
):
    """Get chart data for the dashboard."""
    # Severity distribution (of open incidents)
    sev_query = (
        select(Incident.severity, func.count(Incident.id))
        .where(Incident.status.in_(["new", "in_progress"]))
        .group_by(Incident.severity)
    )
    sev_result = await session.execute(sev_query)
    sev_dict = dict(sev_result.all())

    severity_dist = SeverityDistribution(
        low=sev_dict.get("low", 0),
        medium=sev_dict.get("medium", 0),
        high=sev_dict.get("high", 0),
        critical=sev_dict.get("critical", 0),
    )

    # Alerts by source family
    source_query = (
        select(NormalizedAlert.source_family, func.count(NormalizedAlert.id))
        .group_by(NormalizedAlert.source_family)
    )
    source_result = await session.execute(source_query)
    alerts_by_source = [
        SourceDistribution(source=s, count=c) for s, c in source_result.all()
    ]

    # Recent alerts (last 20)
    recent_query = (
        select(NormalizedAlert)
        .order_by(NormalizedAlert.event_time.desc())
        .limit(20)
    )
    recent_result = await session.execute(recent_query)
    recent_alerts = [
        RecentAlert(
            id=str(a.id),
            event_name=a.event_name,
            severity=a.severity,
            source_ip=a.source_ip,
            user_name=a.user_name,
            event_time=a.event_time,
            source_family=a.source_family,
        )
        for a in recent_result.scalars().all()
    ]

    # Recent incidents (last 10)
    inc_query = (
        select(Incident)
        .order_by(Incident.created_at.desc())
        .limit(10)
    )
    inc_result = await session.execute(inc_query)
    recent_incidents = [
        {
            "id": str(inc.id),
            "incident_number": inc.incident_number,
            "title": inc.title,
            "severity": inc.severity,
            "severity_score": inc.severity_score,
            "status": inc.status,
            "classification": inc.classification,
            "alert_count": inc.alert_count,
            "created_at": inc.created_at.isoformat(),
        }
        for inc in inc_result.scalars().all()
    ]

    return DashboardCharts(
        severity_distribution=severity_dist,
        alerts_by_source=alerts_by_source,
        recent_alerts=recent_alerts,
        recent_incidents=recent_incidents,
    )
