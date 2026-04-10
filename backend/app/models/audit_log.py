"""
AuditLog — minimal audit trail for incident actions.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditLog(Base):
    """Minimal audit trail recording who did what to which incident."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    action: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="created, status_changed, summary_generated, alert_attached, recalculated"
    )
    actor: Mapped[str] = mapped_column(
        String(100), nullable=False, default="system",
        comment="Who performed the action: system, api, analyst_name"
    )
    details: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="Action-specific details"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<AuditLog action={self.action} actor={self.actor} incident={self.incident_id}>"
