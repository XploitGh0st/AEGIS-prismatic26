"""
CorrelationMatch — explainability record for why alerts were grouped into an incident.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import PortableJSON, PortableUUID


class CorrelationMatch(Base):
    """
    Stores the correlation reason codes for why a specific alert was
    attached to a specific incident. Provides full auditability.
    """

    __tablename__ = "correlation_matches"

    id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    normalized_alert_id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), ForeignKey("normalized_alerts.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # ── Score breakdown ──────────────────────────────────
    total_score: Mapped[int] = mapped_column(
        Integer, nullable=False,
        comment="Total correlation score that led to attachment"
    )
    reason_codes: Mapped[dict] = mapped_column(
        PortableJSON(), nullable=False,
        comment="Individual scoring reasons, e.g. {same_user: 20, same_source_ip: 15, ...}"
    )

    # ── Context ──────────────────────────────────────────
    matched_entity: Mapped[str | None] = mapped_column(
        String(255), nullable=True,
        comment="Primary entity that caused the match (IP, user, host)"
    )
    match_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="automatic",
        comment="automatic, manual, session_chain"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # ── Relationships ────────────────────────────────────
    incident = relationship("Incident", back_populates="correlation_matches")

    def __repr__(self) -> str:
        return (
            f"<CorrelationMatch score={self.total_score} "
            f"incident={self.incident_id} alert={self.normalized_alert_id}>"
        )
