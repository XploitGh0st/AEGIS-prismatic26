"""
Scenarios API — list and run pre-built demo scenarios.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.services.scenario_service import list_scenarios, run_scenario

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


@router.get("")
async def get_scenarios():
    """List all available demo scenarios."""
    return {"scenarios": list_scenarios()}


@router.post("/run/{scenario_name}")
async def execute_scenario(
    scenario_name: str,
    session: AsyncSession = Depends(get_db_session),
):
    """Run a scenario by name — ingests all alerts from the scenario file."""
    try:
        result = await run_scenario(session, scenario_name)
        return result
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_name}' not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
