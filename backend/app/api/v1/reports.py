"""
Reports API — generate and download investigation reports.

Endpoints:
- GET /api/v1/incidents/{incident_id}/report/pdf — download PDF report
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.core.logging import get_logger
from app.models.incident import Incident
from app.models.incident_alert_link import IncidentAlertLink
from app.models.incident_summary import IncidentSummary
from app.models.normalized_alert import NormalizedAlert
from app.models.correlation_match import CorrelationMatch
from app.services.rca_service import build_rca_bundle
from app.services.report_service import generate_incident_pdf
from app.services.summary_service import generate_summary

log = get_logger("reports_api")
router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/incidents/{incident_id}/pdf")
async def download_incident_pdf(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    """
    Generate and download a comprehensive PDF investigation report for an incident.

    The report includes:
    - Executive summary
    - Incident metadata and scoring
    - Entity inventory
    - Attack timeline
    - MITRE ATT&CK mapping
    - Correlation analysis
    - Observed facts
    - Root cause hypothesis
    - Recommended actions
    - MemPalace intelligence context
    - Raw evidence appendix
    """
    # Load incident
    result = await session.execute(
        select(Incident).where(Incident.id == uuid.UUID(incident_id))
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Build RCA bundle
    rca_bundle = await build_rca_bundle(session, incident)

    # Load alerts
    links_result = await session.execute(
        select(IncidentAlertLink).where(
            IncidentAlertLink.incident_id == incident.id
        )
    )
    links = list(links_result.scalars().all())
    alert_ids = [link.normalized_alert_id for link in links]

    alerts = []
    if alert_ids:
        alerts_result = await session.execute(
            select(NormalizedAlert)
            .where(NormalizedAlert.id.in_(alert_ids))
            .order_by(NormalizedAlert.event_time)
        )
        alerts = list(alerts_result.scalars().all())

    # Load summaries
    summaries_result = await session.execute(
        select(IncidentSummary)
        .where(IncidentSummary.incident_id == incident.id)
        .order_by(IncidentSummary.version.desc())
    )
    summaries = list(summaries_result.scalars().all())

    # Ensure we have a summary
    if not summaries:
        try:
            summary = await generate_summary(session, incident, generation_type="deterministic")
            await session.flush()
            summaries = [summary]
        except Exception as e:
            log.warning("summary_gen_for_report_failed", error=str(e))

    # Build incident detail dict for report
    incident_detail = {
        "id": str(incident.id),
        "incident_number": incident.incident_number,
        "title": incident.title,
        "classification": incident.classification,
        "severity": incident.severity,
        "severity_score": incident.severity_score,
        "confidence": incident.confidence,
        "status": incident.status,
        "primary_user": incident.primary_user,
        "primary_host": incident.primary_host,
        "primary_src_ip": incident.primary_src_ip,
        "primary_dst_ip": incident.primary_dst_ip,
        "alert_count": incident.alert_count,
        "mitre_techniques": incident.mitre_techniques,
        "mitre_tactics": incident.mitre_tactics,
        "source_families": incident.source_families,
        "scoring_breakdown": incident.scoring_breakdown,
        "first_seen_at": incident.first_seen_at.isoformat() if incident.first_seen_at else "",
        "last_seen_at": incident.last_seen_at.isoformat() if incident.last_seen_at else "",
        "created_at": incident.created_at.isoformat() if incident.created_at else "",
        "alerts": [
            {
                "id": str(a.id),
                "event_name": a.event_name,
                "event_time": a.event_time.isoformat() if a.event_time else "",
                "severity": a.severity,
                "source_ip": a.source_ip,
                "source_family": a.source_family,
                "description": a.description,
            }
            for a in alerts
        ],
        "summaries": [
            {
                "executive_summary": s.executive_summary,
                "root_cause": s.root_cause,
                "observed_facts": s.observed_facts,
                "recommended_actions": s.recommended_actions,
                "confidence_notes": s.confidence_notes,
                "generation_type": s.generation_type,
                "model_used": s.model_used,
            }
            for s in summaries
        ],
    }

    # Generate PDF
    try:
        pdf_bytes = generate_incident_pdf(incident_detail, rca_bundle)
    except Exception as e:
        log.error("pdf_generation_failed", error=str(e), incident_id=incident_id)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    safe_filename = f"AEGIS_Report_{incident.incident_number}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
