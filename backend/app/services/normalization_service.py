"""
Normalization Service — selects the correct adapter and normalizes raw alerts.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.redis import enqueue
from app.models.normalized_alert import NormalizedAlert
from app.models.raw_alert import RawAlert
from app.services.adapters.base import BaseAdapter, CanonicalAlert
from app.services.adapters.cowrie_splunk_adapter import CowrieSplunkAdapter
from app.services.adapters.edr_adapter import EDRAdapter
from app.services.adapters.ids_adapter import IDSAdapter
from app.services.adapters.siem_adapter import SIEMAdapter
from app.utils.fingerprints import compute_entity_fingerprint

log = get_logger("normalization")

# ── Adapter registry ─────────────────────────────────────
ADAPTERS: list[BaseAdapter] = [
    CowrieSplunkAdapter(),
    SIEMAdapter(),
    EDRAdapter(),
    IDSAdapter(),
]


def get_adapter(source_family: str, source_type: str) -> BaseAdapter | None:
    """Find the adapter that handles this source_family/source_type combo."""
    for adapter in ADAPTERS:
        if adapter.can_handle(source_family, source_type):
            return adapter

    # Fallback: match just the source_family
    family_map = {
        "siem": SIEMAdapter(),
        "edr": EDRAdapter(),
        "ids": IDSAdapter(),
        "honeypot": CowrieSplunkAdapter(),
    }
    return family_map.get(source_family)


async def normalize_raw_alert(
    session: AsyncSession,
    raw_alert_id: str,
) -> NormalizedAlert | None:
    """
    Normalize a raw alert by:
    1. Loading it from DB
    2. Selecting the correct adapter
    3. Running normalization
    4. Computing fingerprint
    5. Persisting the NormalizedAlert
    6. Enqueuing correlation
    """
    # Load raw alert
    result = await session.execute(
        select(RawAlert).where(RawAlert.id == uuid.UUID(raw_alert_id))
    )
    raw_alert = result.scalar_one_or_none()

    if raw_alert is None:
        log.error("raw_alert_not_found", raw_alert_id=raw_alert_id)
        return None

    if raw_alert.processing_status != "pending":
        log.warning(
            "raw_alert_already_processed",
            raw_alert_id=raw_alert_id,
            status=raw_alert.processing_status,
        )
        return None

    # Mark as normalizing
    raw_alert.processing_status = "normalizing"
    await session.flush()

    try:
        # Find adapter
        adapter = get_adapter(raw_alert.source_family, raw_alert.source_type)
        if adapter is None:
            raise ValueError(
                f"No adapter for {raw_alert.source_family}/{raw_alert.source_type}"
            )

        # Normalize
        canonical: CanonicalAlert = adapter.normalize(raw_alert.payload)

        # Compute fingerprint
        fingerprint = compute_entity_fingerprint(
            source_type=canonical.source_type,
            event_name=canonical.event_name,
            source_ip=canonical.source_ip,
            user_name=canonical.user_name,
            host_name=canonical.host_name,
            event_time_str=canonical.event_time.isoformat(),
            extra_keys={
                "session_id": canonical.session_id,
                "raw_command": canonical.raw_command,
            },
        )

        # Create normalized alert
        normalized = NormalizedAlert(
            id=uuid.uuid4(),
            raw_alert_id=raw_alert.id,
            source_family=canonical.source_family,
            source_type=canonical.source_type,
            event_time=canonical.event_time,
            category=canonical.category,
            event_name=canonical.event_name,
            severity=canonical.severity,
            confidence=canonical.confidence,
            user_name=canonical.user_name,
            host_name=canonical.host_name,
            source_ip=canonical.source_ip,
            destination_ip=canonical.destination_ip,
            source_port=canonical.source_port,
            destination_port=canonical.destination_port,
            mitre_technique_ids=canonical.mitre_technique_ids or None,
            mitre_tactic=canonical.mitre_tactic,
            description=canonical.description,
            risk_flags=canonical.risk_flags or None,
            raw_command=canonical.raw_command,
            session_id=canonical.session_id,
            extra_data=canonical.extra_data,
            entity_fingerprint=fingerprint,
        )

        session.add(normalized)
        raw_alert.processing_status = "normalized"
        await session.flush()

        # Enqueue correlation
        await enqueue("queue:correlate", {
            "normalized_alert_id": str(normalized.id),
        })

        log.info(
            "alert_normalized",
            normalized_id=str(normalized.id),
            event_name=canonical.event_name,
            severity=canonical.severity,
            source_ip=canonical.source_ip,
        )

        return normalized

    except Exception as e:
        raw_alert.processing_status = "failed"
        raw_alert.error_message = str(e)
        await session.flush()
        log.error(
            "normalization_failed",
            raw_alert_id=raw_alert_id,
            error=str(e),
        )
        return None
