"""
Summary schemas — response models for AI-generated summaries.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SummaryGenerateRequest(BaseModel):
    """Request to generate or regenerate a summary for an incident."""

    force_regenerate: bool = Field(
        False,
        description="If true, regenerate even if a current summary exists",
    )
    generation_type: str = Field(
        "ai_generated",
        pattern=r"^(ai_generated|deterministic)$",
        description="Type of summary to generate",
    )


class SummaryResponse(BaseModel):
    """Summary generation result."""

    incident_id: str
    summary_id: str
    version: int
    generation_type: str
    executive_summary: str
    root_cause: str | None = None
    observed_facts: list[str] | None = None
    recommended_actions: list[str] | None = None
    confidence_notes: str | None = None
    model_used: str | None = None
    generation_time_ms: int | None = None
    validation_passed: bool | None = None
