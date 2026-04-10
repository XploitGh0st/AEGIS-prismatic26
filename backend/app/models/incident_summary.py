"""
IncidentSummary — versioned AI or deterministic summaries for incidents.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.types import PortableJSON, PortableUUID


class IncidentSummary(Base):
    """
    Stores versioned investigation summaries for an incident.
    Can be AI-generated (GPT-4.5) or deterministic (template fallback).
    """

    __tablename__ = "incident_summaries"

    id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PortableUUID(), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1,
        comment="Summary version (incremented on regeneration)"
    )
    generation_type: Mapped[str] = mapped_column(
        String(30), nullable=False,
        comment="ai_generated, deterministic, manual"
    )

    # ── Summary content ──────────────────────────────────
    executive_summary: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Top-level plain-language summary"
    )
    root_cause: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Root cause analysis"
    )
    observed_facts: Mapped[list | None] = mapped_column(
        PortableJSON(), nullable=True,
        comment="List of confirmed observations"
    )
    recommended_actions: Mapped[list | None] = mapped_column(
        PortableJSON(), nullable=True,
        comment="List of suggested next steps"
    )
    confidence_notes: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Notes on confidence level and data gaps"
    )

    # ── LLM metadata ────────────────────────────────────
    model_used: Mapped[str | None] = mapped_column(
        String(100), nullable=True,
        comment="LLM model identifier"
    )
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    generation_time_ms: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="Time to generate summary in milliseconds"
    )

    # ── Validation ───────────────────────────────────────
    validation_passed: Mapped[bool | None] = mapped_column(
        nullable=True,
        comment="Whether the summary passed hallucination validation"
    )
    validation_errors: Mapped[dict | None] = mapped_column(
        PortableJSON(), nullable=True,
        comment="Details of any validation failures"
    )

    # ── RCA bundle snapshot ──────────────────────────────
    rca_bundle: Mapped[dict | None] = mapped_column(
        PortableJSON(), nullable=True,
        comment="Snapshot of the RCA bundle used to generate this summary"
    )

    # ── Timestamps ───────────────────────────────────────
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # ── Relationships ────────────────────────────────────
    incident = relationship("Incident", back_populates="summaries")

    def __repr__(self) -> str:
        return (
            f"<IncidentSummary incident={self.incident_id} "
            f"v{self.version} type={self.generation_type}>"
        )
