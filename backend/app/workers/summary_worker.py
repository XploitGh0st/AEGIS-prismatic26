"""
Summary Worker — dequeues from queue:summary and generates AI/deterministic summaries.

Usage:
    python -m app.workers.summary_worker
"""

from __future__ import annotations

import asyncio
import uuid

from sqlalchemy import select

from app.core.database import async_session_factory, engine
from app.core.logging import get_logger, setup_logging
from app.core.redis import dequeue, close_redis
from app.models.incident import Incident
from app.services.summary_service import generate_summary
from app.workers.queue import SUMMARY_QUEUE

log = get_logger("summary_worker")


async def run_summary_worker() -> None:
    """Main worker loop — dequeues and generates summaries."""
    setup_logging()
    log.info("summary_worker_started", queue=SUMMARY_QUEUE)

    while True:
        try:
            job = await dequeue(SUMMARY_QUEUE, timeout=5)
            if job is None:
                continue

            incident_id = job.get("incident_id")
            if not incident_id:
                log.warning("invalid_job", job=job)
                continue

            force = job.get("force_regenerate", False)
            gen_type = job.get("generation_type", "ai_generated")

            async with async_session_factory() as session:
                try:
                    result = await session.execute(
                        select(Incident).where(
                            Incident.id == uuid.UUID(incident_id)
                        )
                    )
                    incident = result.scalar_one_or_none()
                    if incident is None:
                        log.warning("incident_not_found", incident_id=incident_id)
                        continue

                    summary = await generate_summary(
                        session, incident,
                        force_regenerate=force,
                        generation_type=gen_type,
                    )
                    await session.commit()
                    log.info(
                        "summary_generated",
                        incident_id=incident_id,
                        summary_id=str(summary.id),
                        version=summary.version,
                    )
                except Exception as e:
                    await session.rollback()
                    log.error(
                        "summary_error",
                        incident_id=incident_id,
                        error=str(e),
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("worker_error", error=str(e))
            await asyncio.sleep(1)

    await close_redis()
    await engine.dispose()
    log.info("summary_worker_stopped")


if __name__ == "__main__":
    asyncio.run(run_summary_worker())
