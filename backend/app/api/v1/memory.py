"""
Memory API — MemPalace intelligence endpoints.

Endpoints:
- GET /api/v1/memory/status — palace statistics
- GET /api/v1/memory/attackers — list all known attackers
- GET /api/v1/memory/attackers/{ip} — query attacker knowledge graph
- GET /api/v1/memory/attackers/{ip}/timeline — attacker timeline
- GET /api/v1/memory/search — search past memories
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.core.logging import get_logger
from app.services.memory_service import (
    get_all_attackers,
    get_attacker_timeline,
    get_palace_stats,
    is_mempalace_available,
    query_attacker,
    search_attacker_memory,
    search_similar_incidents,
)

log = get_logger("memory_api")
router = APIRouter(prefix="/memory", tags=["memory"])


@router.get("/status")
async def memory_status():
    """Get MemPalace status and statistics."""
    return {
        "available": is_mempalace_available(),
        "stats": get_palace_stats(),
    }


@router.get("/attackers")
async def list_attackers():
    """List all known attacker entities from the knowledge graph."""
    return {
        "attackers": get_all_attackers(),
        "total": len(get_all_attackers()),
    }


@router.get("/attackers/{ip}")
async def get_attacker(ip: str):
    """Query the knowledge graph for all known triples about an attacker IP."""
    triples = query_attacker(ip)
    return {
        "ip": ip,
        "triples": triples,
        "total": len(triples),
    }


@router.get("/attackers/{ip}/timeline")
async def attacker_timeline(ip: str):
    """Get the full chronological timeline of an attacker IP."""
    timeline = get_attacker_timeline(ip)
    return {
        "ip": ip,
        "timeline": timeline,
        "total_events": len(timeline),
    }


@router.get("/search")
async def search_memory(
    q: str = Query(..., description="Search query"),
    wing: str = Query("wing_incidents", description="Memory wing to search"),
    limit: int = Query(10, ge=1, le=50),
):
    """Search past incident and attacker memories."""
    if wing == "wing_attackers":
        results = search_attacker_memory(q, limit=limit)
    elif wing == "wing_incidents":
        results = search_similar_incidents(q, limit=limit)
    else:
        results = []

    return {
        "query": q,
        "wing": wing,
        "results": results,
        "total": len(results),
    }
