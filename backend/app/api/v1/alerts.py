"""
Alerts API — ingest, list, and query normalized alerts.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.core.logging import get_logger
from app.models.normalized_alert import NormalizedAlert
from app.models.raw_alert import RawAlert
from app.schemas.alert_ingest import (
    AlertBulkIngestRequest,
    AlertBulkIngestResponse,
    AlertIngestRequest,
    AlertIngestResponse,
)
from app.schemas.normalized_alert import NormalizedAlertListResponse, NormalizedAlertResponse
from app.services.ingestion_service import ingest_alert, ingest_bulk
from app.services.normalization_service import normalize_raw_alert
from app.services.correlation_service import correlate_alert

log = get_logger("alerts_api")
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("/ingest", response_model=AlertIngestResponse, status_code=201)
async def ingest_single_alert(
    request: AlertIngestRequest,
    session: AsyncSession = Depends(get_db_session),
    sync_processing: bool = Query(False, description="Process synchronously (skip queue)"),
):
    """
    Ingest a single alert from any source.

    By default, the alert is queued for async normalization and correlation.
    Set sync_processing=true to process inline (useful for testing/demo).
    """
    raw_alert = await ingest_alert(session, request)
    await session.flush()

    if sync_processing:
        # Process inline — useful for demo and testing
        normalized = await normalize_raw_alert(session, str(raw_alert.id))
        if normalized:
            await session.flush()
            incident = await correlate_alert(session, str(normalized.id))
            await session.flush()

    return AlertIngestResponse(
        raw_alert_id=str(raw_alert.id),
        status="accepted",
        message="Alert ingested" + (" and processed synchronously" if sync_processing else " and queued for processing"),
    )


@router.post("/bulk", response_model=AlertBulkIngestResponse, status_code=201)
async def ingest_bulk_alerts(
    request: AlertBulkIngestRequest,
    session: AsyncSession = Depends(get_db_session),
    sync_processing: bool = Query(False, description="Process synchronously"),
):
    """Ingest multiple alerts in a single batch (max 500)."""
    raw_alerts = await ingest_bulk(session, request.alerts)
    await session.flush()

    results = []
    for raw_alert in raw_alerts:
        if sync_processing:
            normalized = await normalize_raw_alert(session, str(raw_alert.id))
            if normalized:
                await session.flush()
                await correlate_alert(session, str(normalized.id))
                await session.flush()

        results.append(AlertIngestResponse(
            raw_alert_id=str(raw_alert.id),
            status="accepted",
        ))

    return AlertBulkIngestResponse(
        accepted=len(results),
        rejected=len(request.alerts) - len(results),
        alerts=results,
    )


@router.get("", response_model=NormalizedAlertListResponse)
async def list_alerts(
    session: AsyncSession = Depends(get_db_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None),
    source_family: str | None = Query(None),
    source_ip: str | None = Query(None),
    category: str | None = Query(None),
):
    """List normalized alerts with optional filters."""
    query = select(NormalizedAlert)

    if severity:
        query = query.where(NormalizedAlert.severity == severity)
    if source_family:
        query = query.where(NormalizedAlert.source_family == source_family)
    if source_ip:
        query = query.where(NormalizedAlert.source_ip == source_ip)
    if category:
        query = query.where(NormalizedAlert.category == category)

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_query)).scalar() or 0

    # Paginate
    query = query.order_by(NormalizedAlert.event_time.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await session.execute(query)
    alerts = result.scalars().all()

    return NormalizedAlertListResponse(
        total=total,
        page=page,
        page_size=page_size,
        alerts=[
            NormalizedAlertResponse(
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
            for a in alerts
        ],
    )


@router.get("/{alert_id}", response_model=NormalizedAlertResponse)
async def get_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    """Get a single normalized alert by ID."""
    result = await session.execute(
        select(NormalizedAlert).where(
            NormalizedAlert.id == uuid.UUID(alert_id)
        )
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return NormalizedAlertResponse(
        id=str(alert.id),
        raw_alert_id=str(alert.raw_alert_id),
        source_family=alert.source_family,
        source_type=alert.source_type,
        event_time=alert.event_time,
        category=alert.category,
        event_name=alert.event_name,
        severity=alert.severity,
        confidence=alert.confidence,
        user_name=alert.user_name,
        host_name=alert.host_name,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        source_port=alert.source_port,
        destination_port=alert.destination_port,
        mitre_technique_ids=alert.mitre_technique_ids,
        mitre_tactic=alert.mitre_tactic,
        description=alert.description,
        risk_flags=alert.risk_flags,
        raw_command=alert.raw_command,
        session_id=alert.session_id,
        extra_data=alert.extra_data,
        entity_fingerprint=alert.entity_fingerprint,
        normalized_at=alert.normalized_at,
    )
