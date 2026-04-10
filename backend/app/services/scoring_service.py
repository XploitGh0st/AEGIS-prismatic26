"""
Scoring Service — computes additive severity scores for incidents.

Score formula:
    base_signal_score (15–35)
    + asset_criticality_bonus (+10/+15)
    + privileged_identity_bonus (+10)
    + multi_source_bonus (+8/+12)
    + execution_bonus (+10)
    + privilege_escalation_bonus (+20)
    + exfiltration_bonus (+15)
    + attack_chain_bonus (+10)
    + alert_volume_bonus (+5/+8)
    - duplicate_noise_penalty (-10)
    - benign_context_penalty (-15)

    Clamped to 0..100
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.incident import Incident


# MITRE technique sets for category bonuses
EXECUTION_TECHNIQUES = {"T1059", "T1204", "T1053", "T1072"}
PRIVESC_TECHNIQUES = {"T1548", "T1134", "T1055", "T1068"}
EXFIL_TECHNIQUES = {"T1041", "T1048", "T1567"}
PERSISTENCE_TECHNIQUES = {"T1543", "T1547", "T1078"}

# Attack chain sequences (technique lists)
ATTACK_CHAINS = [
    ["T1046", "T1110", "T1078", "T1059", "T1105"],
    ["T1110", "T1078", "T1059"],
    ["T1078", "T1059", "T1105"],
    ["T1059", "T1105", "T1041"],
]

# Privileged usernames
PRIVILEGED_USERS = {"root", "administrator", "admin", "system", "nt authority\\system"}


def compute_severity_score(incident: "Incident") -> int:
    """
    Compute the composite severity score for an incident.
    Returns integer 0–100.
    """
    score = 0
    breakdown: dict[str, int] = {}
    techniques = set(incident.mitre_techniques or [])
    tactics = set(incident.mitre_tactics or [])

    # ── Base signal score (15–35) ────────────────────────
    base = _base_score(incident.classification)
    score += base
    breakdown["base_signal"] = base

    # ── Privileged identity bonus (+10) ──────────────────
    if incident.primary_user and incident.primary_user.lower() in PRIVILEGED_USERS:
        score += 10
        breakdown["privileged_identity"] = 10

    # ── Multi-source bonus (+8/+12) ─────────────────────
    families = set(incident.source_families or [])
    if len(families) >= 3:
        score += 12
        breakdown["multi_source"] = 12
    elif len(families) >= 2:
        score += 8
        breakdown["multi_source"] = 8

    # ── Execution bonus (+10) ────────────────────────────
    if techniques & EXECUTION_TECHNIQUES:
        score += 10
        breakdown["execution"] = 10

    # ── Privilege escalation bonus (+20) ─────────────────
    if techniques & PRIVESC_TECHNIQUES:
        score += 20
        breakdown["privilege_escalation"] = 20

    # ── Exfiltration bonus (+15) ─────────────────────────
    if techniques & EXFIL_TECHNIQUES:
        score += 15
        breakdown["exfiltration"] = 15

    # ── Attack chain bonus (+10) ─────────────────────────
    for chain in ATTACK_CHAINS:
        chain_set = set(chain)
        if len(techniques & chain_set) >= 3:
            score += 10
            breakdown["attack_chain"] = 10
            break

    # ── Alert volume bonus (+5/+8) ──────────────────────
    if incident.alert_count >= 10:
        score += 8
        breakdown["alert_volume"] = 8
    elif incident.alert_count >= 5:
        score += 5
        breakdown["alert_volume"] = 5

    # ── Persistence bonus (+5) ──────────────────────────
    if techniques & PERSISTENCE_TECHNIQUES:
        score += 5
        breakdown["persistence"] = 5

    # ── Clamp to 0–100 ──────────────────────────────────
    score = max(0, min(100, score))

    # Store breakdown
    incident.scoring_breakdown = breakdown

    return score


def severity_label(score: int) -> str:
    """Convert a numeric score to a severity label."""
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"


def _base_score(classification: str) -> int:
    """Base score by incident classification."""
    base_scores = {
        "account_compromise": 35,
        "malware_execution": 30,
        "privilege_escalation": 35,
        "possible_exfiltration": 30,
        "brute_force_attempt": 20,
        "reconnaissance": 15,
    }
    return base_scores.get(classification, 20)
