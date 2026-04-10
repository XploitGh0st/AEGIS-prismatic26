"""
IncidentAlertLink — many-to-many relationship between incidents and normalized alerts.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import PortableUUID


class IncidentAlertLink(Base):
    """Links a normalized alert to an incident with metadata about when/how it was attached."""

    __tablename__ = "incident_alert_links"

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
    attached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    attach_reason: Mapped[str] = mapped_column(
        String(50), nullable=False, default="correlation",
        comment="How the alert was attached: correlation, manual, scenario"
    )

    # ── Relationships ────────────────────────────────────
    incident = relationship("Incident", back_populates="alert_links")
    normalized_alert = relationship("NormalizedAlert", lazy="selectin")

    def __repr__(self) -> str:
        return (
            f"<IncidentAlertLink incident={self.incident_id} "
            f"alert={self.normalized_alert_id}>"
        )
