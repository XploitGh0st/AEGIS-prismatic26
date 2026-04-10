"""
Memory Service — wraps MemPalace read/write operations for AEGIS.

Provides a clean interface for:
- Storing incident summaries to the palace
- Querying attacker knowledge graph
- Searching past incident memory
- Managing specialist agent diaries

Falls back gracefully when MemPalace is not installed or disabled.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("memory")
settings = get_settings()

# ── MemPalace availability check ─────────────────────────
_mempalace_available = False
try:
    if settings.mempalace_enabled:
        from mempalace.knowledge_graph import KnowledgeGraph
        from mempalace.searcher import search_memories
        from mempalace.miner import mine_text
        _mempalace_available = True
        log.info("mempalace_loaded", palace_path=settings.mempalace_palace_path)
except ImportError:
    log.info("mempalace_not_installed", msg="MemPalace features disabled — install with: pip install mempalace")
except Exception as e:
    log.warning("mempalace_init_error", error=str(e))


def is_mempalace_available() -> bool:
    """Check if MemPalace is installed and enabled."""
    return _mempalace_available and settings.mempalace_enabled


# ── Knowledge Graph Operations ───────────────────────────

def add_attacker_triple(
    src_ip: str,
    predicate: str,
    obj: str,
    valid_from: str | None = None,
) -> bool:
    """
    Add a triple to the attacker knowledge graph.
    
    Examples:
        add_attacker_triple("185.220.101.45", "used_technique", "T1110_brute_force")
        add_attacker_triple("185.220.101.45", "targeted_host", "svr04")
        add_attacker_triple("185.220.101.45", "downloaded_file", "bot.sh_sha:e3b0c4")
    """
    if not is_mempalace_available():
        log.debug("mempalace_skip", op="add_triple")
        return False

    try:
        kg = KnowledgeGraph(palace_path=settings.mempalace_palace_path)
        kg.add_triple(
            src_ip,
            predicate,
            obj,
            valid_from=valid_from or datetime.utcnow().isoformat(),
        )
        log.info("kg_triple_added", subject=src_ip, predicate=predicate, object=obj)
        return True
    except Exception as e:
        log.error("kg_add_error", error=str(e))
        return False


def query_attacker(src_ip: str) -> list[dict]:
    """
    Query the knowledge graph for all known triples about an attacker IP.
    Returns list of {predicate, object, valid_from} dicts.
    """
    if not is_mempalace_available():
        return []

    try:
        kg = KnowledgeGraph(palace_path=settings.mempalace_palace_path)
        result = kg.query_entity(src_ip)
        log.info("kg_query", ip=src_ip, results=len(result) if result else 0)
        return result if isinstance(result, list) else []
    except Exception as e:
        log.error("kg_query_error", error=str(e), ip=src_ip)
        return []


def get_attacker_timeline(src_ip: str) -> list[dict]:
    """
    Get the full chronological timeline of an attacker IP across all sessions.
    """
    if not is_mempalace_available():
        return []

    try:
        kg = KnowledgeGraph(palace_path=settings.mempalace_palace_path)
        timeline = kg.timeline(src_ip)
        log.info("kg_timeline", ip=src_ip, entries=len(timeline) if timeline else 0)
        return timeline if isinstance(timeline, list) else []
    except Exception as e:
        log.error("kg_timeline_error", error=str(e), ip=src_ip)
        return []


# ── Memory Search Operations ────────────────────────────

def search_attacker_memory(src_ip: str, limit: int = 5) -> list[dict]:
    """
    Search for prior verbatim memories about an attacker IP.
    Returns past summaries, analyst notes, and investigation context.
    """
    if not is_mempalace_available():
        return []

    try:
        results = search_memories(
            f"attacker {src_ip}",
            palace_path=settings.mempalace_palace_path,
            wing="wing_attackers",
        )
        log.info("memory_search", query=f"attacker {src_ip}", results=len(results) if results else 0)
        return results[:limit] if isinstance(results, list) else []
    except Exception as e:
        log.error("memory_search_error", error=str(e))
        return []


def search_similar_incidents(
    classification: str,
    primary_technique: str | None = None,
    limit: int = 5,
) -> list[dict]:
    """
    Search for similar past incidents by classification and technique.
    """
    if not is_mempalace_available():
        return []

    try:
        query = f"{classification}"
        if primary_technique:
            query += f" {primary_technique}"

        results = search_memories(
            query,
            palace_path=settings.mempalace_palace_path,
            wing="wing_incidents",
        )
        log.info("similar_search", query=query, results=len(results) if results else 0)
        return results[:limit] if isinstance(results, list) else []
    except Exception as e:
        log.error("similar_search_error", error=str(e))
        return []


# ── Memory Write Operations ─────────────────────────────

async def save_incident_to_palace(
    incident_id: str,
    incident_number: str,
    classification: str,
    primary_src_ip: str | None,
    summary_text: str,
    mitre_techniques: list[str] | None = None,
) -> bool:
    """
    Save a finalized incident summary to the palace for future recall.
    Also updates the attacker knowledge graph with confirmed TTPs.
    """
    if not is_mempalace_available():
        return False

    try:
        # Save the full summary to wing_incidents
        mine_text(
            text=summary_text,
            palace_path=settings.mempalace_palace_path,
            wing="wing_incidents",
            hall="hall_facts",
            room=classification,
            metadata={
                "incident_id": incident_id,
                "incident_number": incident_number,
                "src_ip": primary_src_ip,
            },
        )

        # Update knowledge graph with confirmed TTPs
        if primary_src_ip and mitre_techniques:
            kg = KnowledgeGraph(palace_path=settings.mempalace_palace_path)
            for technique in mitre_techniques:
                kg.add_triple(
                    primary_src_ip,
                    "used_technique",
                    technique,
                    valid_from=datetime.utcnow().isoformat(),
                )

        log.info(
            "incident_saved_to_palace",
            incident_id=incident_id,
            classification=classification,
            src_ip=primary_src_ip,
        )
        return True

    except Exception as e:
        log.error("palace_save_error", error=str(e), incident_id=incident_id)
        return False


async def save_analyst_decision(
    incident_id: str,
    decision: str,
    analyst: str = "system",
) -> bool:
    """
    Save an analyst decision to the SOC analyst wing.
    """
    if not is_mempalace_available():
        return False

    try:
        mine_text(
            text=f"Analyst {analyst} decided: {decision} for incident {incident_id}",
            palace_path=settings.mempalace_palace_path,
            wing="wing_soc_analyst",
            hall="hall_preferences",
            room="decisions",
            metadata={"incident_id": incident_id, "analyst": analyst},
        )
        return True
    except Exception as e:
        log.error("analyst_save_error", error=str(e))
        return False


# ── Wake-Up Context ──────────────────────────────────────

def get_wake_up_context() -> str:
    """
    Get the MemPalace L0+L1 wake-up context (~170 tokens) for injection
    into the AI summary system prompt.
    
    Returns empty string if MemPalace is not available.
    """
    if not is_mempalace_available():
        return ""

    try:
        # Attempt to read wake-up context from the configured wing
        results = search_memories(
            "recent attacker activity summary",
            palace_path=settings.mempalace_palace_path,
            wing=settings.mempalace_wake_up_wing,
        )
        if results:
            # Concatenate top results into a context block
            context_items = results[:3] if isinstance(results, list) else []
            context = "\n".join(
                str(item.get("text", item) if isinstance(item, dict) else item)
                for item in context_items
            )
            return context[:500]  # Cap at ~170 tokens
        return ""
    except Exception as e:
        log.error("wake_up_error", error=str(e))
        return ""


# ── Enrichment for RCA Service ───────────────────────────

def enrich_rca_bundle(bundle: dict) -> dict:
    """
    Enrich an RCA bundle with MemPalace context before LLM summarization.
    
    Adds:
    - attacker_history: knowledge graph triples for the attacker IP
    - prior_incidents_memory: similar past incidents from verbatim memory
    - prior_memory_verbatim: raw past summaries about this attacker
    """
    if not is_mempalace_available():
        return bundle

    incident = bundle.get("incident", {})
    entities = bundle.get("entities", {})
    src_ips = entities.get("source_ips", [])
    classification = incident.get("classification", "")

    # Pull attacker history from KG
    if src_ips:
        primary_ip = src_ips[0]
        bundle["attacker_history"] = query_attacker(primary_ip)
        bundle["prior_memory_verbatim"] = search_attacker_memory(primary_ip, limit=3)
    else:
        bundle["attacker_history"] = []
        bundle["prior_memory_verbatim"] = []

    # Pull similar past incidents
    techniques = bundle.get("mitre_techniques", [])
    primary_technique = techniques[0].get("id") if techniques else None
    bundle["prior_incidents_memory"] = search_similar_incidents(
        classification, primary_technique, limit=3
    )

    return bundle
