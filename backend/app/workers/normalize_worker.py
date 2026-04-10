"""
Normalize Worker — dequeues from queue:normalize and runs the normalization pipeline.

Usage:
    python -m app.workers.normalize_worker
"""

from __future__ import annotations

import asyncio

from app.core.database import async_session_factory, engine
from app.core.logging import get_logger, setup_logging
from app.core.redis import dequeue, close_redis
from app.services.normalization_service import normalize_raw_alert
from app.workers.queue import NORMALIZE_QUEUE

log = get_logger("normalize_worker")


async def run_normalize_worker() -> None:
    """Main worker loop — dequeues and normalizes raw alerts."""
    setup_logging()
    log.info("normalize_worker_started", queue=NORMALIZE_QUEUE)

    while True:
        try:
            job = await dequeue(NORMALIZE_QUEUE, timeout=5)
            if job is None:
                continue

            raw_alert_id = job.get("raw_alert_id")
            if not raw_alert_id:
                log.warning("invalid_job", job=job)
                continue

            async with async_session_factory() as session:
                try:
                    result = await normalize_raw_alert(session, raw_alert_id)
                    await session.commit()
                    if result:
                        log.info(
                            "normalized",
                            raw_alert_id=raw_alert_id,
                            normalized_id=str(result.id),
                        )
                except Exception as e:
                    await session.rollback()
                    log.error("normalize_error", raw_alert_id=raw_alert_id, error=str(e))

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("worker_error", error=str(e))
            await asyncio.sleep(1)

    await close_redis()
    await engine.dispose()
    log.info("normalize_worker_stopped")


if __name__ == "__main__":
    asyncio.run(run_normalize_worker())
