"""
Health endpoint — service status check.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings
from app.utils.datetime import utcnow

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.app_env,
        "timestamp": utcnow().isoformat(),
        "version": "0.1.0",
    }


@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check with dependency status."""
    checks = {
        "api": "healthy",
        "database": "unknown",
        "redis": "unknown",
    }

    # Check database
    try:
        from app.core.database import engine
        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
        checks["database"] = "healthy"
    except Exception as e:
        checks["database"] = f"unhealthy: {str(e)[:100]}"

    # Check Redis
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = "healthy"
    except Exception as e:
        checks["redis"] = f"unhealthy: {str(e)[:100]}"

    overall = "healthy" if all(
        v == "healthy" for v in checks.values()
    ) else "degraded"

    return {
        "status": overall,
        "checks": checks,
        "timestamp": utcnow().isoformat(),
    }
