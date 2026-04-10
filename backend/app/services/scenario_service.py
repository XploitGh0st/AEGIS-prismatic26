"""
Scenario Service — loads and runs pre-built mock scenarios.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.schemas.alert_ingest import AlertIngestRequest
from app.services.ingestion_service import ingest_alert

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
            })
        except Exception as e:
            log.warning("scenario_parse_error", file=path.name, error=str(e))

    return scenarios


async def run_scenario(
    session: AsyncSession,
    scenario_name: str,
) -> dict[str, Any]:
    """
    Load and run a scenario by name.
    Returns a summary of what was ingested.
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

    for alert_data in alerts_data:
        try:
            request = AlertIngestRequest(**alert_data)
            await ingest_alert(session, request)
            ingested += 1
        except Exception as e:
            log.error("scenario_alert_error", scenario=scenario_name, error=str(e))
            errors += 1

    log.info(
        "scenario_executed",
        scenario=scenario_name,
        ingested=ingested,
        errors=errors,
    )

    return {
        "scenario": scenario_name,
        "description": data.get("description", ""),
        "total_alerts": len(alerts_data),
        "ingested": ingested,
        "errors": errors,
    }
