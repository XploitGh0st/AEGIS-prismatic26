"""
API Router — mounts all v1 route modules.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.scenarios import router as scenarios_router
from app.api.v1.health import router as health_router
from app.api.v1.pcap import router as pcap_router
from app.api.v1.reports import router as reports_router
from app.api.v1.memory import router as memory_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(dashboard_router)
api_router.include_router(scenarios_router)
api_router.include_router(pcap_router)
api_router.include_router(reports_router)
api_router.include_router(memory_router)

