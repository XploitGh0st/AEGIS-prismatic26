"""
Incident — primary incident record holding severity, classification, status.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import PortableArray, PortableJSON, PortableUUID


class Incident(Base):
    """
    An incident groups correlated alerts into a single investigation unit.

    Incidents are the primary entity that SOC analysts interact with.
    """

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), primary_key=True, default=uuid.uuid4
    )
    incident_number: Mapped[str] = mapped_column(
        String(30), nullable=False, unique=True, index=True,
        comment="Human-readable ID: INC-YYYYMMDD-NNNN"
    )

    # ── Classification ───────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(255), nullable=False,
        comment="Auto-generated title"
    )
    classification: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="account_compromise, malware_execution, brute_force_attempt, etc."
    )

    # ── Severity ─────────────────────────────────────────
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True,
        comment="low, medium, high, critical"
    )
    severity_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="0–100 composite severity score"
    )
    confidence: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.5,
        comment="0.0–1.0 overall confidence"
    )

    # ── Status ───────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="new", index=True,
        comment="new, in_progress, resolved, false_positive, closed"
    )

    # ── Entity summary ───────────────────────────────────
    primary_user: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    primary_host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    primary_src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    primary_dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)

    # ── MITRE ATT&CK ────────────────────────────────────
    mitre_techniques: Mapped[list[str] | None] = mapped_column(
        PortableArray(String(20)), nullable=True,
        comment="Aggregated MITRE techniques from all alerts"
    )
    mitre_tactics: Mapped[list[str] | None] = mapped_column(
        PortableArray(String(50)), nullable=True,
        comment="Aggregated MITRE tactics"
    )

    # ── Counts ───────────────────────────────────────────
    alert_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1,
        comment="Number of correlated alerts"
    )
    source_families: Mapped[list[str] | None] = mapped_column(
        PortableArray(String(50)), nullable=True,
        comment="Unique source families: siem, edr, ids, honeypot"
    )

    # ── Scoring breakdown ────────────────────────────────
    scoring_breakdown: Mapped[dict | None] = mapped_column(
        PortableJSON(), nullable=True,
        comment="Detailed score component breakdown"
    )

    # ── Timestamps ───────────────────────────────────────
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        comment="Earliest alert event_time"
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        comment="Latest alert event_time"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    # ── Relationships ────────────────────────────────────
    alert_links = relationship("IncidentAlertLink", back_populates="incident", lazy="selectin")
    summaries = relationship("IncidentSummary", back_populates="incident", lazy="selectin")
    correlation_matches = relationship("CorrelationMatch", back_populates="incident", lazy="selectin")

    def __repr__(self) -> str:
        return (
            f"<Incident {self.incident_number} type={self.classification} "
            f"severity={self.severity}({self.severity_score}) status={self.status}>"
        )
