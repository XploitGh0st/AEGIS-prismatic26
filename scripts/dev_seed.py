"""
Dev Seed Script — loads all mock scenarios into the AEGIS backend for development/testing.

Usage:
    python scripts/dev_seed.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.core.database import async_session_factory, init_db, close_db, engine
from app.core.logging import setup_logging, get_logger
from app.core.redis import close_redis
from app.schemas.alert_ingest import AlertIngestRequest
from app.services.ingestion_service import ingest_alert
from app.services.normalization_service import normalize_raw_alert
from app.services.correlation_service import correlate_alert

log = get_logger("dev_seed")

SCENARIOS_DIR = Path(__file__).parent.parent / "mock-data" / "scenarios"


async def seed_scenario(scenario_file: Path) -> dict:
    """Load and process a single scenario file synchronously."""
    with open(scenario_file) as f:
        data = json.load(f)

    name = scenario_file.stem
    alerts_data = data.get("alerts", [])
    print(f"\n  📁 {name} ({len(alerts_data)} alerts)")

    ingested = 0
    normalized = 0
    correlated = 0

    for alert_data in alerts_data:
        async with async_session_factory() as session:
            try:
                # Ingest
                request = AlertIngestRequest(**alert_data)
                raw_alert = await ingest_alert(session, request)
                await session.flush()
                ingested += 1

                # Normalize
                norm = await normalize_raw_alert(session, str(raw_alert.id))
                if norm:
                    await session.flush()
                    normalized += 1

                    # Correlate
                    incident = await correlate_alert(session, str(norm.id))
                    await session.flush()
                    correlated += 1

                await session.commit()

            except Exception as e:
                await session.rollback()
                print(f"    ⚠️  Error: {e}")

    print(f"    ✅ Ingested: {ingested}, Normalized: {normalized}, Correlated: {correlated}")
    return {"name": name, "ingested": ingested, "normalized": normalized, "correlated": correlated}


async def main():
    setup_logging()
    print("=" * 60)
    print("  AEGIS Dev Seed — Loading mock scenarios")
    print("=" * 60)

    # Initialize database
    await init_db()

    if not SCENARIOS_DIR.exists():
        print(f"ERROR: Scenarios directory not found: {SCENARIOS_DIR}")
        return

    scenario_files = sorted(SCENARIOS_DIR.glob("*.json"))
    if not scenario_files:
        print("No scenario files found.")
        return

    print(f"\nFound {len(scenario_files)} scenarios:")
    results = []

    for sf in scenario_files:
        result = await seed_scenario(sf)
        results.append(result)

    # Summary
    print("\n" + "=" * 60)
    print("  SEED SUMMARY")
    print("=" * 60)
    total_ingested = sum(r["ingested"] for r in results)
    total_normalized = sum(r["normalized"] for r in results)
    total_correlated = sum(r["correlated"] for r in results)
    print(f"  Total Ingested:   {total_ingested}")
    print(f"  Total Normalized: {total_normalized}")
    print(f"  Total Correlated: {total_correlated}")
    print("=" * 60)

    await close_redis()
    await close_db()


if __name__ == "__main__":
    asyncio.run(main())
