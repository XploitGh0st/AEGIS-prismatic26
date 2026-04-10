"""
Correlation Service — groups normalized alerts into incidents.

This is the core intelligence of AEGIS. It uses a scoring-based approach
to determine whether a new alert belongs to an existing incident or needs a new one.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.correlation_match import CorrelationMatch
from app.models.incident import Incident
from app.models.incident_alert_link import IncidentAlertLink
from app.models.normalized_alert import NormalizedAlert
from app.services.scoring_service import compute_severity_score, severity_label
from app.services.classification_service import classify_incident
from app.utils.datetime import utcnow, format_incident_number

log = get_logger("correlation")
settings = get_settings()

# ── Correlation scoring weights ──────────────────────────
CORRELATION_WEIGHTS: dict[str, int] = {
    "same_user": 20,
    "same_user_service_account": 8,
    "same_host": 15,
    "same_source_ip": 15,
    "same_destination_ip": 10,
    "same_session": 25,          # Cowrie session = same attacker chain
    "time_within_5m": 10,
    "time_within_15m": 5,
    "mitre_overlap": 12,
    "attack_chain_match": 18,
    "high_value_asset_match": 5,
    "duplicate_fingerprint_penalty": -30,
    "contradictory_context_penalty": -20,
}

# Service accounts get reduced user weight
SERVICE_ACCOUNTS = {"system", "root", "admin", "svc_", "service", "daemon", "nobody"}

# MITRE attack chain sequences (ordered)
ATTACK_CHAINS: list[list[str]] = [
    ["T1046", "T1110", "T1078", "T1059", "T1105"],  # recon → brute → login → exec → download
    ["T1110", "T1078", "T1059"],                      # brute → login → exec
    ["T1078", "T1059", "T1105"],                      # login → exec → download
    ["T1059", "T1105", "T1041"],                      # exec → download → exfil
    ["T1110", "T1078", "T1548"],                      # brute → login → privesc
]


async def correlate_alert(
    session: AsyncSession,
    normalized_alert_id: str,
) -> Incident:
    """
    Correlate a normalized alert into an incident.

    1. Load the alert
    2. Find open incidents within the lookback window
    3. Score each candidate incident
    4. If best score >= threshold → attach to that incident
    5. If no match → create new incident
    6. Store correlation reason codes
    7. Recalculate severity and classification
    """
    # Load the alert
    result = await session.execute(
        select(NormalizedAlert).where(
            NormalizedAlert.id == uuid.UUID(normalized_alert_id)
        )
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise ValueError(f"NormalizedAlert {normalized_alert_id} not found")

    # Find candidate incidents
    lookback = utcnow() - timedelta(minutes=settings.correlation_lookback_minutes)
    candidate_query = select(Incident).where(
        and_(
            Incident.status.in_(["new", "in_progress"]),
            Incident.last_seen_at >= lookback,
        )
    )
    candidates_result = await session.execute(candidate_query)
    candidates = list(candidates_result.scalars().all())

    # Score each candidate
    best_incident: Incident | None = None
    best_score: int = 0
    best_reasons: dict[str, int] = {}

    for incident in candidates:
        score, reasons = await _compute_correlation_score(session, alert, incident)
        if score > best_score:
            best_score = score
            best_incident = incident
            best_reasons = reasons

    # Decision: attach or create new
    threshold = settings.correlation_attach_threshold

    if best_incident is not None and best_score >= threshold:
        # Attach to existing incident
        incident = best_incident
        match_type = "automatic"

        log.info(
            "alert_correlated",
            alert_id=str(alert.id),
            incident_id=str(incident.id),
            incident_number=incident.incident_number,
            score=best_score,
            reasons=best_reasons,
        )
    else:
        # Create new incident
        incident = await _create_incident(session, alert)
        best_reasons = {"new_incident": 0}
        best_score = 0
        match_type = "new_incident"

        log.info(
            "new_incident_created",
            alert_id=str(alert.id),
            incident_id=str(incident.id),
            incident_number=incident.incident_number,
        )

    # Create link
    link = IncidentAlertLink(
        id=uuid.uuid4(),
        incident_id=incident.id,
        normalized_alert_id=alert.id,
        attach_reason="correlation" if match_type == "automatic" else "new_incident",
    )
    session.add(link)

    # Store correlation match
    if match_type == "automatic":
        corr_match = CorrelationMatch(
            id=uuid.uuid4(),
            incident_id=incident.id,
            normalized_alert_id=alert.id,
            total_score=best_score,
            reason_codes=best_reasons,
            matched_entity=alert.source_ip or alert.user_name,
            match_type=match_type,
        )
        session.add(corr_match)

    # Update incident
    await _update_incident(session, incident, alert)

    await session.flush()
    return incident


async def _compute_correlation_score(
    session: AsyncSession,
    alert: NormalizedAlert,
    incident: Incident,
) -> tuple[int, dict[str, int]]:
    """Compute correlation score between an alert and an incident."""
    score = 0
    reasons: dict[str, int] = {}

    # Load incident's existing alerts for comparison
    links_result = await session.execute(
        select(IncidentAlertLink).where(
            IncidentAlertLink.incident_id == incident.id
        )
    )
    links = list(links_result.scalars().all())

    alert_ids = [link.normalized_alert_id for link in links]
    if alert_ids:
        existing_alerts_result = await session.execute(
            select(NormalizedAlert).where(
                NormalizedAlert.id.in_(alert_ids)
            )
        )
        existing_alerts = list(existing_alerts_result.scalars().all())
    else:
        existing_alerts = []

    # ── Same user ────────────────────────────────────────
    if alert.user_name and incident.primary_user:
        if alert.user_name == incident.primary_user:
            is_service = any(
                alert.user_name.lower().startswith(s) for s in SERVICE_ACCOUNTS
            )
            weight = CORRELATION_WEIGHTS["same_user_service_account"] if is_service else CORRELATION_WEIGHTS["same_user"]
            score += weight
            reasons["same_user"] = weight

    # ── Same host ────────────────────────────────────────
    if alert.host_name and incident.primary_host:
        if alert.host_name == incident.primary_host:
            score += CORRELATION_WEIGHTS["same_host"]
            reasons["same_host"] = CORRELATION_WEIGHTS["same_host"]

    # ── Same source IP ───────────────────────────────────
    if alert.source_ip and incident.primary_src_ip:
        if alert.source_ip == incident.primary_src_ip:
            score += CORRELATION_WEIGHTS["same_source_ip"]
            reasons["same_source_ip"] = CORRELATION_WEIGHTS["same_source_ip"]

    # ── Same destination IP ──────────────────────────────
    if alert.destination_ip and incident.primary_dst_ip:
        if alert.destination_ip == incident.primary_dst_ip:
            score += CORRELATION_WEIGHTS["same_destination_ip"]
            reasons["same_destination_ip"] = CORRELATION_WEIGHTS["same_destination_ip"]

    # ── Same Cowrie session (very strong signal) ─────────
    if alert.session_id:
        for ea in existing_alerts:
            if ea.session_id and ea.session_id == alert.session_id:
                score += CORRELATION_WEIGHTS["same_session"]
                reasons["same_session"] = CORRELATION_WEIGHTS["same_session"]
                break

    # ── Time proximity ───────────────────────────────────
    time_diff = abs((alert.event_time - incident.last_seen_at).total_seconds())
    if time_diff <= 300:  # 5 minutes
        score += CORRELATION_WEIGHTS["time_within_5m"]
        reasons["time_within_5m"] = CORRELATION_WEIGHTS["time_within_5m"]
    elif time_diff <= 900:  # 15 minutes
        score += CORRELATION_WEIGHTS["time_within_15m"]
        reasons["time_within_15m"] = CORRELATION_WEIGHTS["time_within_15m"]

    # ── MITRE technique overlap ──────────────────────────
    if alert.mitre_technique_ids and incident.mitre_techniques:
        overlap = set(alert.mitre_technique_ids) & set(incident.mitre_techniques)
        if overlap:
            score += CORRELATION_WEIGHTS["mitre_overlap"]
            reasons["mitre_overlap"] = CORRELATION_WEIGHTS["mitre_overlap"]

    # ── Attack chain detection ───────────────────────────
    if alert.mitre_technique_ids and incident.mitre_techniques:
        combined = set(incident.mitre_techniques) | set(alert.mitre_technique_ids)
        for chain in ATTACK_CHAINS:
            chain_set = set(chain)
            if len(combined & chain_set) >= 3:  # at least 3 techniques match a chain
                score += CORRELATION_WEIGHTS["attack_chain_match"]
                reasons["attack_chain_match"] = CORRELATION_WEIGHTS["attack_chain_match"]
                break

    # ── Penalties ────────────────────────────────────────
    # Duplicate fingerprint
    for ea in existing_alerts:
        if ea.entity_fingerprint == alert.entity_fingerprint:
            score += CORRELATION_WEIGHTS["duplicate_fingerprint_penalty"]
            reasons["duplicate_fingerprint_penalty"] = CORRELATION_WEIGHTS["duplicate_fingerprint_penalty"]
            break

    return score, reasons


async def _create_incident(
    session: AsyncSession,
    alert: NormalizedAlert,
) -> Incident:
    """Create a new incident from a single alert."""
    # Generate incident number
    today = utcnow()
    count_result = await session.execute(
        select(func.count(Incident.id)).where(
            Incident.created_at >= today.replace(hour=0, minute=0, second=0, microsecond=0)
        )
    )
    today_count = count_result.scalar() or 0

    incident_number = format_incident_number(today, today_count + 1)

    # Initial classification
    classification = _initial_classification(alert)

    # Initial severity
    severity_score = _initial_severity_score(alert)
    sev_label = severity_label(severity_score)

    # Build title
    title = _build_title(alert, classification)

    incident = Incident(
        id=uuid.uuid4(),
        incident_number=incident_number,
        title=title,
        classification=classification,
        severity=sev_label,
        severity_score=severity_score,
        confidence=alert.confidence,
        status="new",
        primary_user=alert.user_name,
        primary_host=alert.host_name,
        primary_src_ip=alert.source_ip,
        primary_dst_ip=alert.destination_ip,
        mitre_techniques=alert.mitre_technique_ids,
        mitre_tactics=[alert.mitre_tactic] if alert.mitre_tactic else None,
        alert_count=1,
        source_families=[alert.source_family],
        first_seen_at=alert.event_time,
        last_seen_at=alert.event_time,
    )

    session.add(incident)
    await session.flush()
    return incident


async def _update_incident(
    session: AsyncSession,
    incident: Incident,
    new_alert: NormalizedAlert,
) -> None:
    """Update incident metadata after a new alert is attached."""
    incident.alert_count += 1

    # Update time window
    if new_alert.event_time < incident.first_seen_at:
        incident.first_seen_at = new_alert.event_time
    if new_alert.event_time > incident.last_seen_at:
        incident.last_seen_at = new_alert.event_time

    # Merge MITRE techniques
    existing_techniques = set(incident.mitre_techniques or [])
    new_techniques = set(new_alert.mitre_technique_ids or [])
    incident.mitre_techniques = list(existing_techniques | new_techniques)

    # Merge tactics
    existing_tactics = set(incident.mitre_tactics or [])
    if new_alert.mitre_tactic:
        existing_tactics.add(new_alert.mitre_tactic)
    incident.mitre_tactics = list(existing_tactics)

    # Merge source families
    existing_families = set(incident.source_families or [])
    existing_families.add(new_alert.source_family)
    incident.source_families = list(existing_families)

    # Update primary entities if not set
    if not incident.primary_user and new_alert.user_name:
        incident.primary_user = new_alert.user_name
    if not incident.primary_host and new_alert.host_name:
        incident.primary_host = new_alert.host_name
    if not incident.primary_src_ip and new_alert.source_ip:
        incident.primary_src_ip = new_alert.source_ip

    # Recalculate severity and classification
    incident.severity_score = compute_severity_score(incident)
    incident.severity = severity_label(incident.severity_score)
    incident.classification = classify_incident(incident)
    incident.title = _build_title_from_incident(incident)

    # Recalculate confidence (weighted average)
    incident.confidence = min(
        0.99,
        incident.confidence + (new_alert.confidence * 0.1)
    )


def _initial_classification(alert: NormalizedAlert) -> str:
    """Initial classification from a single alert."""
    if alert.category == "authentication" and alert.event_name == "failed_login":
        return "brute_force_attempt"
    elif alert.category == "authentication" and alert.event_name == "successful_login":
        return "account_compromise"
    elif alert.category == "execution":
        return "malware_execution"
    elif alert.category == "network" and "scan" in (alert.event_name or ""):
        return "reconnaissance"
    else:
        return "reconnaissance"


def _initial_severity_score(alert: NormalizedAlert) -> int:
    """Initial severity score from a single alert."""
    base_scores = {
        "low": 15,
        "medium": 25,
        "high": 35,
        "critical": 50,
    }
    return base_scores.get(alert.severity, 20)


def _build_title(alert: NormalizedAlert, classification: str) -> str:
    """Build an incident title from the first alert."""
    class_labels = {
        "account_compromise": "Potential account compromise",
        "malware_execution": "Suspicious execution activity",
        "brute_force_attempt": "Brute force attack",
        "reconnaissance": "Reconnaissance activity",
        "privilege_escalation": "Privilege escalation attempt",
        "possible_exfiltration": "Possible data exfiltration",
    }
    label = class_labels.get(classification, "Security incident")
    target = alert.host_name or alert.source_ip or "unknown"
    return f"{label} on {target}"


def _build_title_from_incident(incident: Incident) -> str:
    """Rebuild title from incident data (after reclassification)."""
    class_labels = {
        "account_compromise": "Potential account compromise",
        "malware_execution": "Suspicious execution activity",
        "brute_force_attempt": "Brute force attack",
        "reconnaissance": "Reconnaissance activity",
        "privilege_escalation": "Privilege escalation attempt",
        "possible_exfiltration": "Possible data exfiltration",
    }
    label = class_labels.get(incident.classification, "Security incident")
    target = incident.primary_host or incident.primary_src_ip or "unknown"
    return f"{label} on {target}"
