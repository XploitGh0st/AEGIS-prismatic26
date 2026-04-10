"""
RawAlert — immutable storage for raw inbound JSON payloads.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.types import PortableJSON, PortableUUID


class RawAlert(Base):
    """Stores the original, unmodified alert payload as received from any source."""

    __tablename__ = "raw_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), primary_key=True, default=uuid.uuid4
    )
    source_family: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="Origin family: siem, edr, ids, honeypot"
    )
    source_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True,
        comment="Specific source: splunk_mock, crowdstrike_mock, cowrie_splunk, etc."
    )
    external_alert_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, unique=True, index=True,
        comment="Dedup key from originating system"
    )
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True,
        comment="When the event actually occurred (from source)"
    )
    payload: Mapped[dict] = mapped_column(
        PortableJSON(), nullable=False,
        comment="Full raw JSON payload from the source"
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
        comment="When AEGIS received this alert"
    )
    processing_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", index=True,
        comment="pending → normalizing → normalized → failed"
    )
    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Error details if normalization failed"
    )

    def __repr__(self) -> str:
        return (
            f"<RawAlert id={self.id} source={self.source_family}/{self.source_type} "
            f"status={self.processing_status}>"
        )
