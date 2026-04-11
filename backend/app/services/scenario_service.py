"""
Scenario Service — loads and runs pre-built mock scenarios through the full AEGIS pipeline.

Full pipeline: Load JSON → Ingest → Normalize → Correlate → Score → Classify → AI Summary
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.incident import Incident
from app.models.incident_alert_link import IncidentAlertLink
from app.schemas.alert_ingest import AlertIngestRequest
from app.services.ingestion_service import ingest_alert
from app.services.normalization_service import normalize_raw_alert
from app.services.correlation_service import correlate_alert
from app.services.summary_service import generate_summary

log = get_logger("scenarios")

SCENARIOS_DIR = Path(__file__).parent.parent.parent.parent / "mock-data" / "scenarios"


def list_scenarios() -> list[dict[str, Any]]:
    """List all available mock scenarios."""
    scenarios = []
    if not SCENARIOS_DIR.exists():
        return scenarios

    for path in sorted(SCENARIOS_DIR.glob("*.json")):
        try:
            with open(path) as f:
                data = json.load(f)

            scenarios.append({
                "name": path.stem,
                "filename": path.name,
                "description": data.get("description", path.stem),
                "alert_count": len(data.get("alerts", [])),
                "expected_incidents": data.get("expected_incidents", 1),
                "expected_severity": data.get("expected_severity", "unknown"),
                "expected_classification": data.get("expected_classification", "unknown"),
                "has_correlation_notes": "correlation_notes" in data,
            })
        except Exception as e:
            log.warning("scenario_parse_error", file=path.name, error=str(e))

    return scenarios


async def run_scenario(
    session: AsyncSession,
    scenario_name: str,
    auto_summarize: bool = True,
    generation_type: str = "ai_generated",
) -> dict[str, Any]:
    """
    Load and run a scenario through the full AEGIS pipeline.

    Pipeline: Ingest → Normalize → Correlate → Score → Classify → AI Summary

    Returns a detailed summary of incidents created with AI-generated investigation narratives.
    """
    scenario_file = SCENARIOS_DIR / f"{scenario_name}.json"
    if not scenario_file.exists():
        raise FileNotFoundError(f"Scenario '{scenario_name}' not found")

    with open(scenario_file) as f:
        data = json.load(f)

    alerts_data = data.get("alerts", [])
    if not alerts_data:
        raise ValueError(f"Scenario '{scenario_name}' has no alerts")

    ingested = 0
    errors = 0
    error_details = []
    incident_ids: set[str] = set()

    # ── Phase 1: Ingest → Normalize → Correlate ─────────────────
    for alert_data in alerts_data:
        try:
            # Use savepoint so one failed alert doesn't poison the session
            async with session.begin_nested():
                request = AlertIngestRequest(**alert_data)
                raw_alert = await ingest_alert(session, request)
                await session.flush()

                # Normalize immediately (sync processing)
                normalized = await normalize_raw_alert(session, str(raw_alert.id))
                if normalized:
                    await session.flush()

                    # Correlate → Score → Classify
                    incident = await correlate_alert(session, str(normalized.id))
                    await session.flush()
                    incident_ids.add(str(incident.id))

            ingested += 1

        except Exception as e:
            import traceback as tb
            error_details.append({"alert_index": errors, "error": str(e), "traceback": tb.format_exc()})
            log.error("scenario_alert_error", scenario=scenario_name, error=str(e))
            errors += 1

    # ── Phase 2: Auto-generate AI summaries for each incident ────
    summaries_generated = 0
    incident_details = []

    if auto_summarize and incident_ids:
        for inc_id in incident_ids:
            try:
                import uuid as _uuid
                result = await session.execute(
                    select(Incident).where(Incident.id == _uuid.UUID(inc_id))
                )
                incident = result.scalar_one_or_none()
                if incident is None:
                    continue

                summary = await generate_summary(
                    session, incident,
                    force_regenerate=True,
                    generation_type=generation_type,
                )
                await session.flush()
                summaries_generated += 1

                incident_details.append({
                    "incident_id": inc_id,
                    "incident_number": incident.incident_number,
                    "title": incident.title,
                    "classification": incident.classification,
                    "severity": incident.severity,
                    "severity_score": incident.severity_score,
                    "alert_count": incident.alert_count,
                    "mitre_techniques": incident.mitre_techniques or [],
                    "summary_type": summary.generation_type,
                    "executive_summary": summary.executive_summary,
                    "root_cause": summary.root_cause,
                    "model_used": summary.model_used,
                })

            except Exception as e:
                log.error("scenario_summary_error", incident_id=inc_id, error=str(e))

    log.info(
        "scenario_executed",
        scenario=scenario_name,
        ingested=ingested,
        errors=errors,
        incidents=len(incident_ids),
        summaries=summaries_generated,
    )

    return {
        "scenario": scenario_name,
        "description": data.get("description", ""),
        "expected_incidents": data.get("expected_incidents", 0),
        "expected_classification": data.get("expected_classification", ""),
        "total_alerts": len(alerts_data),
        "ingested": ingested,
        "errors": errors,
        "incidents_created": len(incident_ids),
        "incidents_summarized": summaries_generated,
        "incidents": incident_details,
        "error_details": error_details if error_details else None,
    }
