"""
Scenarios API — list and run pre-built demo scenarios through the full AEGIS pipeline.

Each scenario automatically runs: Ingest → Normalize → Correlate → Score → Classify → AI Summary
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.services.scenario_service import list_scenarios, run_scenario

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


@router.get("")
async def get_scenarios():
    """List all available demo scenarios with metadata."""
    return {"scenarios": list_scenarios()}


@router.post("/run/{scenario_name}")
async def execute_scenario(
    scenario_name: str,
    session: AsyncSession = Depends(get_db_session),
    auto_summarize: bool = Query(True, description="Auto-generate AI summaries for correlated incidents"),
    generation_type: str = Query("ai_generated", description="Summary type: ai_generated or deterministic"),
):
    """
    Run a scenario by name — ingests all alerts and runs the full AEGIS pipeline.

    Pipeline: Ingest → Normalize → Correlate → Score → Classify → AI Summary (Mistral AI)

    The response includes all correlated incidents with their AI-generated
    investigation summaries, MITRE ATT&CK mappings, and severity scores.
    """
    try:
        result = await run_scenario(
            session,
            scenario_name,
            auto_summarize=auto_summarize,
            generation_type=generation_type,
        )
        return result
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
