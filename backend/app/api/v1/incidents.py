"""
Incidents API — list, detail, status update, recalculate, and summary generation.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.core.logging import get_logger
from app.core.redis import enqueue
from app.models.incident import Incident
from app.models.incident_alert_link import IncidentAlertLink
from app.models.normalized_alert import NormalizedAlert
from app.models.correlation_match import CorrelationMatch
from app.models.incident_summary import IncidentSummary
from app.schemas.incident import (
    CorrelationMatchResponse,
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentResponse,
    IncidentStatusUpdate,
    IncidentSummaryResponse,
)
from app.schemas.normalized_alert import NormalizedAlertResponse
from app.services.scoring_service import compute_severity_score, severity_label
from app.services.classification_service import classify_incident
from app.services.summary_service import generate_summary

log = get_logger("incidents_api")
router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    session: AsyncSession = Depends(get_db_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    classification: str | None = Query(None),
    source_ip: str | None = Query(None),
):
    """List incidents with optional filters."""
    query = select(Incident)

    if severity:
        query = query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
    if classification:
        query = query.where(Incident.classification == classification)
    if source_ip:
        query = query.where(Incident.primary_src_ip == source_ip)

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_query)).scalar() or 0

    # Paginate
    query = query.order_by(Incident.severity_score.desc(), Incident.last_seen_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await session.execute(query)
    incidents = result.scalars().all()

    return IncidentListResponse(
        total=total,
        page=page,
        page_size=page_size,
        incidents=[_to_incident_response(inc) for inc in incidents],
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    """Get full incident detail with alerts, summaries, and correlation explanation."""
    result = await session.execute(
        select(Incident).where(Incident.id == uuid.UUID(incident_id))
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

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

    # Load correlation matches
    corr_result = await session.execute(
        select(CorrelationMatch)
        .where(CorrelationMatch.incident_id == incident.id)
    )
    corr_matches = list(corr_result.scalars().all())

    return IncidentDetailResponse(
        id=str(incident.id),
        incident_number=incident.incident_number,
        title=incident.title,
        classification=incident.classification,
        severity=incident.severity,
        severity_score=incident.severity_score,
        confidence=incident.confidence,
        status=incident.status,
        primary_user=incident.primary_user,
        primary_host=incident.primary_host,
        primary_src_ip=incident.primary_src_ip,
        primary_dst_ip=incident.primary_dst_ip,
        alert_count=incident.alert_count,
        mitre_techniques=incident.mitre_techniques,
        mitre_tactics=incident.mitre_tactics,
        source_families=incident.source_families,
        scoring_breakdown=incident.scoring_breakdown,
        first_seen_at=incident.first_seen_at,
        last_seen_at=incident.last_seen_at,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        alerts=[_to_alert_response(a) for a in alerts],
        summaries=[_to_summary_response(s) for s in summaries],
        correlation_matches=[_to_corr_response(c) for c in corr_matches],
    )


@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    update: IncidentStatusUpdate,
    session: AsyncSession = Depends(get_db_session),
):
    """Update the status of an incident."""
    result = await session.execute(
        select(Incident).where(Incident.id == uuid.UUID(incident_id))
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    incident.status = update.status
    await session.flush()

    log.info(
        "status_updated",
        incident_id=incident_id,
        old_status=old_status,
        new_status=update.status,
    )

    return {
        "incident_id": incident_id,
        "old_status": old_status,
        "new_status": update.status,
    }


@router.post("/{incident_id}/recalculate")
async def recalculate_incident(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    """Re-run severity scoring and classification for an incident."""
    result = await session.execute(
        select(Incident).where(Incident.id == uuid.UUID(incident_id))
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_score = incident.severity_score
    old_class = incident.classification

    incident.severity_score = compute_severity_score(incident)
    incident.severity = severity_label(incident.severity_score)
    incident.classification = classify_incident(incident)
    await session.flush()

    return {
        "incident_id": incident_id,
        "old_severity_score": old_score,
        "new_severity_score": incident.severity_score,
        "old_classification": old_class,
        "new_classification": incident.classification,
    }


@router.post("/{incident_id}/generate-summary")
async def trigger_summary(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
    force: bool = Query(False),
    sync_processing: bool = Query(True),
    generation_type: str = Query("deterministic"),
):
    """Generate or regenerate a summary for this incident."""
    result = await session.execute(
        select(Incident).where(Incident.id == uuid.UUID(incident_id))
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    if sync_processing:
        summary = await generate_summary(
            session, incident,
            force_regenerate=force,
            generation_type=generation_type,
        )
        await session.flush()
        return _to_summary_response(summary)
    else:
        await enqueue("queue:summary", {
            "incident_id": incident_id,
            "force_regenerate": force,
            "generation_type": generation_type,
        })
        return {"status": "queued", "incident_id": incident_id}


# ── Helper converters ────────────────────────────────────

def _to_incident_response(inc: Incident) -> IncidentResponse:
    return IncidentResponse(
        id=str(inc.id),
        incident_number=inc.incident_number,
        title=inc.title,
        classification=inc.classification,
        severity=inc.severity,
        severity_score=inc.severity_score,
        confidence=inc.confidence,
        status=inc.status,
        primary_user=inc.primary_user,
        primary_host=inc.primary_host,
        primary_src_ip=inc.primary_src_ip,
        alert_count=inc.alert_count,
        mitre_techniques=inc.mitre_techniques,
        source_families=inc.source_families,
        first_seen_at=inc.first_seen_at,
        last_seen_at=inc.last_seen_at,
        created_at=inc.created_at,
    )


def _to_alert_response(a: NormalizedAlert) -> NormalizedAlertResponse:
    return NormalizedAlertResponse(
        id=str(a.id),
        raw_alert_id=str(a.raw_alert_id),
        source_family=a.source_family,
        source_type=a.source_type,
        event_time=a.event_time,
        category=a.category,
        event_name=a.event_name,
        severity=a.severity,
        confidence=a.confidence,
        user_name=a.user_name,
        host_name=a.host_name,
        source_ip=a.source_ip,
        destination_ip=a.destination_ip,
        source_port=a.source_port,
        destination_port=a.destination_port,
        mitre_technique_ids=a.mitre_technique_ids,
        mitre_tactic=a.mitre_tactic,
        description=a.description,
        risk_flags=a.risk_flags,
        raw_command=a.raw_command,
        session_id=a.session_id,
        extra_data=a.extra_data,
        entity_fingerprint=a.entity_fingerprint,
        normalized_at=a.normalized_at,
    )


def _to_summary_response(s: IncidentSummary) -> IncidentSummaryResponse:
    return IncidentSummaryResponse(
        id=str(s.id),
        version=s.version,
        generation_type=s.generation_type,
        executive_summary=s.executive_summary,
        root_cause=s.root_cause,
        observed_facts=s.observed_facts,
        recommended_actions=s.recommended_actions,
        confidence_notes=s.confidence_notes,
        model_used=s.model_used,
        generation_time_ms=s.generation_time_ms,
        validation_passed=s.validation_passed,
        generated_at=s.generated_at,
    )


def _to_corr_response(c: CorrelationMatch) -> CorrelationMatchResponse:
    return CorrelationMatchResponse(
        total_score=c.total_score,
        reason_codes=c.reason_codes,
        matched_entity=c.matched_entity,
        match_type=c.match_type,
    )
