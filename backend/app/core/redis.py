"""
AEGIS Redis — connection pool and queue helpers.
"""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis

from app.core.config import get_settings

settings = get_settings()

redis_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    """Get or create the global async Redis connection."""
    global redis_pool
    if redis_pool is None:
        redis_pool = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=20,
        )
    return redis_pool


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global redis_pool
    if redis_pool is not None:
        await redis_pool.close()
        redis_pool = None


async def enqueue(queue_name: str, payload: dict[str, Any]) -> None:
    """Push a JSON payload onto a Redis list (queue)."""
    import asyncio
    try:
        r = await get_redis()
        await asyncio.wait_for(r.rpush(queue_name, json.dumps(payload)), timeout=2.0)
    except Exception as e:
        print(f"Skipping Redis enqueue for {queue_name} (Redis unavailable): {e}")


async def dequeue(queue_name: str, timeout: int = 5) -> dict[str, Any] | None:
    """
    Blocking pop from a Redis list (queue).
    Returns None if timeout elapses without a message.
    """
    r = await get_redis()
    result = await r.blpop(queue_name, timeout=timeout)
    if result is None:
        return None
    _, data = result
    return json.loads(data)


async def get_queue_length(queue_name: str) -> int:
    """Get the number of items in a queue."""
    r = await get_redis()
    return await r.llen(queue_name)
