"""
Correlate Worker — dequeues from queue:correlate and runs the correlation engine.

Usage:
    python -m app.workers.correlate_worker
"""

from __future__ import annotations

import asyncio

from app.core.database import async_session_factory, engine
from app.core.logging import get_logger, setup_logging
from app.core.redis import dequeue, close_redis
from app.services.correlation_service import correlate_alert
from app.workers.queue import CORRELATE_QUEUE

log = get_logger("correlate_worker")


async def run_correlate_worker() -> None:
    """Main worker loop — dequeues and correlates normalized alerts."""
    setup_logging()
    log.info("correlate_worker_started", queue=CORRELATE_QUEUE)

    while True:
        try:
            job = await dequeue(CORRELATE_QUEUE, timeout=5)
            if job is None:
                continue

            normalized_alert_id = job.get("normalized_alert_id")
            if not normalized_alert_id:
                log.warning("invalid_job", job=job)
                continue

            async with async_session_factory() as session:
                try:
                    incident = await correlate_alert(session, normalized_alert_id)
                    await session.commit()
                    log.info(
                        "correlated",
                        alert_id=normalized_alert_id,
                        incident_number=incident.incident_number,
                        severity=incident.severity,
                    )
                except Exception as e:
                    await session.rollback()
                    log.error(
                        "correlate_error",
                        alert_id=normalized_alert_id,
                        error=str(e),
                    )

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("worker_error", error=str(e))
            await asyncio.sleep(1)

    await close_redis()
    await engine.dispose()
    log.info("correlate_worker_stopped")


if __name__ == "__main__":
    asyncio.run(run_correlate_worker())
