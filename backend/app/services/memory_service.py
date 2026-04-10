"""
Memory Service — Self-contained MemPalace for AEGIS.

Provides a fully local, file-based implementation of the MemPalace concept:
- Knowledge Graph: JSON-based triple store (subject → predicate → object)
- Memory Store: JSON-based indexed memories with keyword search
- Wake-up Context: Reads most recent attacker summaries for LLM injection

No external dependencies — works out of the box.

Palace structure:
    ~/.aegis/mempalace/
    ├── knowledge_graph.json       # Triple store
    ├── memories/
    │   ├── wing_attackers/        # Attacker memories
    │   ├── wing_incidents/        # Incident summaries
    │   └── wing_soc_analyst/      # Analyst decisions
    └── stats.json                 # Usage statistics
"""

from __future__ import annotations

import json
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("memory")
settings = get_settings()


def _palace_path() -> Path:
    """Resolve the palace directory path."""
    raw = settings.mempalace_palace_path
    p = Path(os.path.expanduser(raw)).resolve()
    return p


def _ensure_palace():
    """Create palace directory structure if it doesn't exist."""
    base = _palace_path()
    (base / "memories" / "wing_attackers").mkdir(parents=True, exist_ok=True)
    (base / "memories" / "wing_incidents").mkdir(parents=True, exist_ok=True)
    (base / "memories" / "wing_soc_analyst").mkdir(parents=True, exist_ok=True)

    kg_path = base / "knowledge_graph.json"
    if not kg_path.exists():
        kg_path.write_text(json.dumps({"triples": [], "entities": {}}, indent=2))

    stats_path = base / "stats.json"
    if not stats_path.exists():
        stats_path.write_text(json.dumps({
            "total_triples": 0,
            "total_memories": 0,
            "created_at": datetime.utcnow().isoformat(),
            "last_updated": datetime.utcnow().isoformat(),
        }, indent=2))


def is_mempalace_available() -> bool:
    """Check if MemPalace is enabled."""
    return settings.mempalace_enabled


# ── Knowledge Graph Operations ───────────────────────────

def _load_kg() -> dict:
    """Load the knowledge graph from disk."""
    _ensure_palace()
    kg_path = _palace_path() / "knowledge_graph.json"
    try:
        return json.loads(kg_path.read_text(encoding="utf-8"))
    except Exception:
        return {"triples": [], "entities": {}}


def _save_kg(kg: dict):
    """Save the knowledge graph to disk."""
    kg_path = _palace_path() / "knowledge_graph.json"
    kg_path.write_text(json.dumps(kg, indent=2, default=str), encoding="utf-8")


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
    """
    if not is_mempalace_available():
        log.debug("mempalace_skip", op="add_triple")
        return False

    try:
        kg = _load_kg()
        triple = {
            "subject": src_ip,
            "predicate": predicate,
            "object": obj,
            "valid_from": valid_from or datetime.utcnow().isoformat(),
            "added_at": datetime.utcnow().isoformat(),
        }

        # Avoid exact duplicates
        for existing in kg["triples"]:
            if (existing["subject"] == src_ip
                    and existing["predicate"] == predicate
                    and existing["object"] == obj):
                return True  # Already exists

        kg["triples"].append(triple)

        # Update entity index
        if src_ip not in kg["entities"]:
            kg["entities"][src_ip] = {
                "first_seen": triple["valid_from"],
                "last_seen": triple["valid_from"],
                "triple_count": 0,
            }
        kg["entities"][src_ip]["last_seen"] = triple["valid_from"]
        kg["entities"][src_ip]["triple_count"] = len(
            [t for t in kg["triples"] if t["subject"] == src_ip]
        )

        _save_kg(kg)
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
        kg = _load_kg()
        results = []
        for triple in kg["triples"]:
            if triple["subject"] == src_ip:
                results.append({
                    "predicate": triple["predicate"],
                    "object": triple["object"],
                    "valid_from": triple["valid_from"],
                })
        log.info("kg_query", ip=src_ip, results=len(results))
        return results
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
        kg = _load_kg()
        timeline = []
        for triple in kg["triples"]:
            if triple["subject"] == src_ip:
                timeline.append({
                    "time": triple["valid_from"],
                    "action": triple["predicate"],
                    "detail": triple["object"],
                })
        # Sort chronologically
        timeline.sort(key=lambda x: x.get("time", ""))
        log.info("kg_timeline", ip=src_ip, entries=len(timeline))
        return timeline
    except Exception as e:
        log.error("kg_timeline_error", error=str(e), ip=src_ip)
        return []


def get_all_attackers() -> list[dict]:
    """List all known attacker entities from the knowledge graph."""
    if not is_mempalace_available():
        return []
    try:
        kg = _load_kg()
        attackers = []
        for entity, meta in kg.get("entities", {}).items():
            attackers.append({
                "ip": entity,
                "first_seen": meta.get("first_seen"),
                "last_seen": meta.get("last_seen"),
                "triple_count": meta.get("triple_count", 0),
            })
        return sorted(attackers, key=lambda x: x.get("last_seen", ""), reverse=True)
    except Exception:
        return []


# ── Memory Search Operations ────────────────────────────

def _memory_dir(wing: str) -> Path:
    """Get the directory for a specific memory wing."""
    return _palace_path() / "memories" / wing


def _save_memory_entry(
    text: str,
    wing: str,
    hall: str = "hall_facts",
    room: str = "general",
    metadata: dict | None = None,
) -> str:
    """Save a memory entry to a wing."""
    _ensure_palace()
    mem_dir = _memory_dir(wing)
    mem_dir.mkdir(parents=True, exist_ok=True)

    entry_id = hashlib.sha256(
        f"{text[:100]}{time.time()}".encode()
    ).hexdigest()[:16]

    entry = {
        "id": entry_id,
        "text": text,
        "wing": wing,
        "hall": hall,
        "room": room,
        "metadata": metadata or {},
        "created_at": datetime.utcnow().isoformat(),
        "keywords": _extract_keywords(text),
    }

    entry_path = mem_dir / f"{entry_id}.json"
    entry_path.write_text(json.dumps(entry, indent=2, default=str), encoding="utf-8")

    # Update stats
    _update_stats("total_memories", 1)

    return entry_id


def _extract_keywords(text: str) -> list[str]:
    """Extract simple keywords from text for search."""
    # Remove common words and split
    stop_words = {
        "the", "a", "an", "is", "was", "are", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "shall",
        "should", "may", "might", "must", "can", "could", "to", "of", "in",
        "for", "on", "with", "at", "by", "from", "as", "into", "through",
        "during", "before", "after", "above", "below", "between", "out",
        "off", "over", "under", "again", "further", "then", "once", "and",
        "but", "or", "nor", "not", "so", "no", "if", "that", "this",
    }
    words = text.lower().split()
    keywords = []
    for word in words:
        clean = "".join(c for c in word if c.isalnum() or c in "._-:/")
        if clean and len(clean) > 2 and clean not in stop_words:
            keywords.append(clean)
    return list(set(keywords))


def search_attacker_memory(src_ip: str, limit: int = 5) -> list[dict]:
    """
    Search for prior verbatim memories about an attacker IP.
    Returns past summaries, analyst notes, and investigation context.
    """
    if not is_mempalace_available():
        return []

    try:
        return _search_wing(f"attacker {src_ip}", "wing_attackers", limit)
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
        query = classification
        if primary_technique:
            query += f" {primary_technique}"
        return _search_wing(query, "wing_incidents", limit)
    except Exception as e:
        log.error("similar_search_error", error=str(e))
        return []


def _search_wing(query: str, wing: str, limit: int = 5) -> list[dict]:
    """Search memories in a specific wing using keyword matching."""
    mem_dir = _memory_dir(wing)
    if not mem_dir.exists():
        return []

    query_keywords = set(_extract_keywords(query))
    if not query_keywords:
        return []

    scored_results = []
    for entry_path in mem_dir.glob("*.json"):
        try:
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            entry_keywords = set(entry.get("keywords", []))

            # Score by keyword overlap
            overlap = query_keywords & entry_keywords
            if overlap:
                score = len(overlap) / max(len(query_keywords), 1)
                scored_results.append({
                    "text": entry.get("text", ""),
                    "score": score,
                    "metadata": entry.get("metadata", {}),
                    "created_at": entry.get("created_at", ""),
                    "room": entry.get("room", ""),
                    "matching_keywords": list(overlap),
                })
        except Exception:
            continue

    # Sort by score descending
    scored_results.sort(key=lambda x: x["score"], reverse=True)
    return scored_results[:limit]


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
        _save_memory_entry(
            text=summary_text,
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
            for technique in mitre_techniques:
                add_attacker_triple(
                    primary_src_ip,
                    "used_technique",
                    technique,
                    valid_from=datetime.utcnow().isoformat(),
                )

        # Save attacker memory
        if primary_src_ip:
            _save_memory_entry(
                text=f"Attacker {primary_src_ip} involved in {classification} incident {incident_number}. {summary_text}",
                wing="wing_attackers",
                hall="hall_facts",
                room=classification,
                metadata={
                    "incident_id": incident_id,
                    "src_ip": primary_src_ip,
                },
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
        _save_memory_entry(
            text=f"Analyst {analyst} decided: {decision} for incident {incident_id}",
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
        # Get recent attacker memories
        results = _search_wing(
            "recent attacker activity summary",
            settings.mempalace_wake_up_wing,
        )
        if results:
            context_items = results[:3]
            context = "\n".join(
                str(item.get("text", ""))
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


# ── Statistics ───────────────────────────────────────────

def _update_stats(field: str, increment: int = 1):
    """Update palace statistics."""
    stats_path = _palace_path() / "stats.json"
    try:
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
        stats[field] = stats.get(field, 0) + increment
        stats["last_updated"] = datetime.utcnow().isoformat()
        stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    except Exception:
        pass


def get_palace_stats() -> dict:
    """Get palace usage statistics."""
    if not is_mempalace_available():
        return {"enabled": False}

    _ensure_palace()
    try:
        stats_path = _palace_path() / "stats.json"
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
        kg = _load_kg()
        stats["enabled"] = True
        stats["total_triples"] = len(kg.get("triples", []))
        stats["total_entities"] = len(kg.get("entities", {}))
        stats["palace_path"] = str(_palace_path())

        # Count memories per wing
        for wing in ["wing_attackers", "wing_incidents", "wing_soc_analyst"]:
            wing_dir = _memory_dir(wing)
            if wing_dir.exists():
                stats[f"{wing}_count"] = len(list(wing_dir.glob("*.json")))
            else:
                stats[f"{wing}_count"] = 0

        return stats
    except Exception as e:
        return {"enabled": True, "error": str(e)}
