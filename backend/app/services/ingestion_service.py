"""
Ingestion Service — receives raw alerts and stores them in the database.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.redis import enqueue
from app.models.raw_alert import RawAlert
from app.schemas.alert_ingest import AlertIngestRequest
from app.utils.datetime import parse_iso

log = get_logger("ingestion")


async def ingest_alert(
    session: AsyncSession,
    request: AlertIngestRequest,
) -> RawAlert:
    """
    Ingest a single raw alert:
    1. Create RawAlert record in database
    2. Enqueue normalization job to Redis
    """
    raw_alert = RawAlert(
        id=uuid.uuid4(),
        source_family=request.source_family,
        source_type=request.source_type,
        external_alert_id=request.external_alert_id,
        event_time=parse_iso(request.event_time),
        payload=request.payload,
        processing_status="pending",
    )

    session.add(raw_alert)
    await session.flush()

    # Enqueue normalization job
    await enqueue("queue:normalize", {
        "raw_alert_id": str(raw_alert.id),
        "source_family": raw_alert.source_family,
        "source_type": raw_alert.source_type,
    })

    log.info(
        "alert_ingested",
        raw_alert_id=str(raw_alert.id),
        source=f"{raw_alert.source_family}/{raw_alert.source_type}",
        external_id=raw_alert.external_alert_id,
    )

    return raw_alert


async def ingest_bulk(
    session: AsyncSession,
    requests: list[AlertIngestRequest],
) -> list[RawAlert]:
    """Ingest multiple alerts in a single transaction."""
    results: list[RawAlert] = []
    for req in requests:
        try:
            raw_alert = await ingest_alert(session, req)
            results.append(raw_alert)
        except Exception as e:
            log.error("bulk_ingest_error", error=str(e), source_type=req.source_type)
            # Continue processing remaining alerts
    return results
