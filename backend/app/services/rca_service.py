"""
RCA Service — builds deterministic Root Cause Analysis bundles for incidents.

The RCA bundle is the structured input that feeds into the AI summary service.
It contains everything the LLM needs to generate an accurate investigation summary.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.services.memory_service import enrich_rca_bundle
from app.models.correlation_match import CorrelationMatch
from app.models.incident import Incident
from app.models.incident_alert_link import IncidentAlertLink
from app.models.normalized_alert import NormalizedAlert

log = get_logger("rca")


async def build_rca_bundle(
    session: AsyncSession,
    incident: Incident,
) -> dict:
    """
    Build a deterministic RCA bundle for an incident.

    The bundle contains:
    - Incident metadata
    - Entity inventory (users, hosts, IPs)
    - Attack timeline (chronological alert sequence)
    - MITRE ATT&CK techniques with labels
    - Observed facts (deterministic, no hallucinations)
    - Root cause hypothesis
    - Recommended actions
    - Correlation explanation
    """
    # Load all alerts for this incident
    links_result = await session.execute(
        select(IncidentAlertLink).where(
            IncidentAlertLink.incident_id == incident.id
        )
    )
    links = list(links_result.scalars().all())

    alert_ids = [link.normalized_alert_id for link in links]
    alerts: list[NormalizedAlert] = []
    if alert_ids:
        alerts_result = await session.execute(
            select(NormalizedAlert)
            .where(NormalizedAlert.id.in_(alert_ids))
            .order_by(NormalizedAlert.event_time)
        )
        alerts = list(alerts_result.scalars().all())

    # Load correlation matches
    corr_result = await session.execute(
        select(CorrelationMatch).where(
            CorrelationMatch.incident_id == incident.id
        )
    )
    correlation_matches = list(corr_result.scalars().all())

    # ── Build entities ───────────────────────────────────
    entities = _extract_entities(alerts)

    # ── Build timeline ───────────────────────────────────
    timeline = _build_timeline(alerts)

    # ── MITRE mapping ────────────────────────────────────
    mitre = _map_mitre(incident, alerts)

    # ── Observed facts ───────────────────────────────────
    facts = _build_facts(incident, alerts)

    # ── Root cause hypothesis ────────────────────────────
    root_cause = _build_root_cause(incident, alerts)

    # ── Recommended actions ──────────────────────────────
    actions = _build_recommended_actions(incident, alerts)

    # ── Correlation explanation ──────────────────────────
    correlation_explanation = _build_correlation_explanation(correlation_matches)

    bundle = {
        "incident": {
            "id": str(incident.id),
            "number": incident.incident_number,
            "title": incident.title,
            "classification": incident.classification,
            "severity": incident.severity,
            "severity_score": incident.severity_score,
            "confidence": incident.confidence,
            "status": incident.status,
            "alert_count": incident.alert_count,
            "first_seen": incident.first_seen_at.isoformat(),
            "last_seen": incident.last_seen_at.isoformat(),
        },
        "entities": entities,
        "timeline": timeline,
        "mitre_techniques": mitre,
        "observed_facts": facts,
        "root_cause_hypothesis": root_cause,
        "recommended_actions": actions,
        "correlation_explanation": correlation_explanation,
        "scoring_breakdown": incident.scoring_breakdown or {},
    }

    # ── MemPalace enrichment (if available) ───────────────
    bundle = enrich_rca_bundle(bundle)

    log.info(
        "rca_bundle_built",
        incident_id=str(incident.id),
        alert_count=len(alerts),
        fact_count=len(facts),
        mempalace_enriched="attacker_history" in bundle,
    )

    return bundle


def _extract_entities(alerts: list[NormalizedAlert]) -> dict:
    """Extract unique entities from alerts."""
    users = set()
    hosts = set()
    src_ips = set()
    dst_ips = set()
    sessions = set()

    for alert in alerts:
        if alert.user_name:
            users.add(alert.user_name)
        if alert.host_name:
            hosts.add(alert.host_name)
        if alert.source_ip:
            src_ips.add(alert.source_ip)
        if alert.destination_ip:
            dst_ips.add(alert.destination_ip)
        if alert.session_id:
            sessions.add(alert.session_id)

    return {
        "users": sorted(users),
        "hosts": sorted(hosts),
        "source_ips": sorted(src_ips),
        "destination_ips": sorted(dst_ips),
        "sessions": sorted(sessions),
    }


def _build_timeline(alerts: list[NormalizedAlert]) -> list[dict]:
    """Build a chronological timeline of events."""
    timeline = []
    for alert in alerts:
        entry = {
            "time": alert.event_time.isoformat(),
            "source": f"[{alert.source_family.upper()}]",
            "event": alert.event_name,
            "severity": alert.severity,
            "description": alert.description or alert.event_name,
        }
        if alert.source_ip:
            entry["source_ip"] = alert.source_ip
        if alert.user_name:
            entry["user"] = alert.user_name
        if alert.raw_command:
            entry["command"] = alert.raw_command
        timeline.append(entry)
    return timeline


def _map_mitre(incident: Incident, alerts: list[NormalizedAlert]) -> list[dict]:
    """Map MITRE techniques with labels."""
    TECHNIQUE_LABELS = {
        "T1046": "Network Service Discovery",
        "T1110": "Brute Force",
        "T1078": "Valid Accounts",
        "T1059": "Command and Scripting Interpreter",
        "T1105": "Ingress Tool Transfer",
        "T1572": "Protocol Tunneling",
        "T1204": "User Execution",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1134": "Access Token Manipulation",
        "T1055": "Process Injection",
        "T1041": "Exfiltration Over C2 Channel",
        "T1071": "Application Layer Protocol",
        "T1543": "Create or Modify System Process",
        "T1547": "Boot or Logon Autostart Execution",
        "T1003": "OS Credential Dumping",
        "T1027": "Obfuscated Files or Information",
        "T1190": "Exploit Public-Facing Application",
        "T1021": "Remote Services",
    }

    techniques = set(incident.mitre_techniques or [])
    result = []
    for tech_id in sorted(techniques):
        result.append({
            "id": tech_id,
            "name": TECHNIQUE_LABELS.get(tech_id, "Unknown Technique"),
        })
    return result


def _build_facts(incident: Incident, alerts: list[NormalizedAlert]) -> list[str]:
    """Build observed facts — deterministic, no speculation."""
    facts = []

    # Count event types
    event_counts: dict[str, int] = {}
    for alert in alerts:
        event_counts[alert.event_name] = event_counts.get(alert.event_name, 0) + 1

    if "failed_login" in event_counts:
        count = event_counts["failed_login"]
        src_ip = incident.primary_src_ip or "unknown"
        facts.append(f"{count} failed login attempt(s) observed from {src_ip}")

    if "successful_login" in event_counts:
        user = incident.primary_user or "unknown"
        facts.append(f"Successful login achieved as user '{user}'")

    if "command_execution" in event_counts:
        count = event_counts["command_execution"]
        facts.append(f"{count} command(s) executed post-authentication")

    if "file_download" in event_counts:
        facts.append("File(s) downloaded from external source")

    if "file_upload" in event_counts:
        facts.append("File(s) uploaded to the system")

    # Risk flags
    all_flags = set()
    for alert in alerts:
        if alert.risk_flags:
            all_flags.update(alert.risk_flags)

    if "suspicious_download" in all_flags:
        facts.append("Suspicious file download detected (potential malware)")
    if "credential_harvesting" in all_flags:
        facts.append("Credential harvesting activity observed")
    if "lateral_movement_attempt" in all_flags:
        facts.append("Lateral movement indicators present")
    if "persistence_attempt" in all_flags:
        facts.append("Persistence mechanism installation attempted")

    # Commands executed
    commands = [a.raw_command for a in alerts if a.raw_command]
    if commands:
        facts.append(f"Commands executed: {', '.join(commands[:5])}")

    return facts


def _build_root_cause(incident: Incident, alerts: list[NormalizedAlert]) -> str:
    """Build a deterministic root cause hypothesis."""
    templates = {
        "cve_exploitation": (
            "Active exploitation of a known CVE vulnerability detected. "
            "Attacker delivered exploit payload targeting a public-facing application, "
            "achieved code execution, and established command-and-control connectivity."
        ),
        "account_compromise": (
            "Credential brute-force attack followed by successful login "
            "and post-authentication activity. Attacker likely used automated "
            "tooling to guess credentials."
        ),
        "malware_execution": (
            "Suspicious process execution detected, possibly through a "
            "downloaded payload or encoded command execution."
        ),
        "brute_force_attempt": (
            "Automated credential guessing attack targeting SSH/authentication "
            "service. Multiple failed login attempts from a single source."
        ),
        "reconnaissance": (
            "Network reconnaissance activity detected — port scanning or "
            "service enumeration from external source."
        ),
        "privilege_escalation": (
            "Attempt to elevate privileges beyond initial access level, "
            "possibly through token manipulation or vulnerability exploitation."
        ),
        "possible_exfiltration": (
            "Suspicious outbound data transfer detected, potentially "
            "representing data exfiltration over C2 channel."
        ),
    }
    return templates.get(
        incident.classification,
        "Automated security incident detected — review timeline for details."
    )


def _build_recommended_actions(
    incident: Incident, alerts: list[NormalizedAlert]
) -> list[str]:
    """Build recommended next steps."""
    actions = []

    if incident.primary_src_ip:
        actions.append(f"Block source IP {incident.primary_src_ip} at firewall")
        actions.append(f"Check threat intelligence feeds for {incident.primary_src_ip}")

    if incident.classification == "account_compromise":
        if incident.primary_user:
            actions.append(f"Force password reset for user '{incident.primary_user}'")
        actions.append("Review authentication logs for the entire time window")
        actions.append("Check for unauthorized sessions or processes")

    if incident.classification in ("malware_execution", "account_compromise"):
        actions.append("Review downloaded files for malware indicators")
        actions.append("Check other hosts for same attacker IP activity")

    if incident.classification == "brute_force_attempt":
        actions.append("Review rate limiting and lockout policies")
        actions.append("Consider implementing fail2ban or equivalent")

    actions.append("Report to threat intelligence team")
    actions.append("Update firewall rules and IDS signatures")

    return actions


def _build_correlation_explanation(
    matches: list[CorrelationMatch],
) -> list[dict]:
    """Format correlation matches for the RCA bundle."""
    explanation = []
    for match in matches:
        explanation.append({
            "total_score": match.total_score,
            "reasons": match.reason_codes,
            "matched_entity": match.matched_entity,
            "type": match.match_type,
        })
    return explanation
