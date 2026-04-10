"""
NormalizedAlert — canonical alert representation after adapter normalization.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import PortableArray, PortableJSON, PortableUUID


class NormalizedAlert(Base):
    """
    Canonical alert record produced by the adapter normalization layer.

    Every raw alert maps 1:1 to a normalized alert. This table stores the
    standardized fields that the correlation engine operates on.
    """

    __tablename__ = "normalized_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), primary_key=True, default=uuid.uuid4
    )
    raw_alert_id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), ForeignKey("raw_alerts.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )

    # ── Source identity ──────────────────────────────────
    source_family: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # ── Canonical fields ─────────────────────────────────
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="authentication, execution, network, endpoint, etc."
    )
    event_name: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="Canonical event name: failed_login, command_execution, etc."
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True,
        comment="low, medium, high, critical"
    )
    confidence: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.5,
        comment="0.0–1.0 confidence in this alert's correctness"
    )

    # ── Entity fields (for correlation) ──────────────────
    user_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    host_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(nullable=True)
    destination_port: Mapped[int | None] = mapped_column(nullable=True)

    # ── MITRE ATT&CK ────────────────────────────────────
    mitre_technique_ids: Mapped[list[str] | None] = mapped_column(
        PortableArray(String(20)), nullable=True,
        comment="E.g. ['T1110', 'T1078']"
    )
    mitre_tactic: Mapped[str | None] = mapped_column(
        String(50), nullable=True,
        comment="E.g. initial-access, execution, persistence"
    )

    # ── Extra context ────────────────────────────────────
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_flags: Mapped[list[str] | None] = mapped_column(
        PortableArray(String(100)), nullable=True,
        comment="E.g. ['suspicious_download', 'credential_harvesting']"
    )
    raw_command: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Original command if applicable (e.g., Cowrie command input)"
    )
    extra_data: Mapped[dict | None] = mapped_column(
        PortableJSON(), nullable=True,
        comment="Additional adapter-specific normalized data"
    )

    # ── Fingerprint ──────────────────────────────────────
    entity_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True,
        comment="SHA-256 hash for deduplication"
    )

    # ── Session tracking (Cowrie-specific) ───────────────
    session_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True, index=True,
        comment="Cowrie session ID for attack chain linking"
    )

    # ── Timestamps ───────────────────────────────────────
    normalized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # ── Relationships ────────────────────────────────────
    raw_alert = relationship("RawAlert", lazy="selectin")

    def __repr__(self) -> str:
        return (
            f"<NormalizedAlert id={self.id} event={self.event_name} "
            f"severity={self.severity} src_ip={self.source_ip}>"
        )
