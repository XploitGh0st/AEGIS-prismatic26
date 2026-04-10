"""
Summary Service — generates AI or deterministic investigation summaries.

Uses Mistral AI (mistral-large) with a validated RCA bundle as input.
Falls back to template-based deterministic summaries if LLM fails.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.incident import Incident
from app.models.incident_summary import IncidentSummary
from app.services.rca_service import build_rca_bundle
from app.services.memory_service import get_wake_up_context, save_incident_to_palace

log = get_logger("summary")
settings = get_settings()

# ── System prompt for AI summarization ───────────────────
SYSTEM_PROMPT = """\
You are a SOC investigation summarization assistant for the AEGIS cybersecurity triage platform.

Your job is to produce a clear, accurate, and actionable investigation summary from the provided structured incident bundle.

Rules:
1. Only reference entities (IPs, users, hosts, techniques) that exist in the provided bundle
2. Do not hallucinate additional context or entities
3. Use professional SOC analyst tone
4. Be specific about what happened, when, and what should be done
5. Structure your response as valid JSON with these exact keys:
   - "executive_summary": string (2-3 sentences)
   - "root_cause": string (1-2 sentences)
   - "observed_facts": list of strings
   - "recommended_actions": list of strings
   - "confidence_notes": string (1 sentence about data quality/gaps)
"""


async def generate_summary(
    session: AsyncSession,
    incident: Incident,
    force_regenerate: bool = False,
    generation_type: str = "ai_generated",
) -> IncidentSummary:
    """
    Generate a summary for an incident.

    1. Build RCA bundle
    2. Try AI generation (if enabled)
    3. Fall back to deterministic template
    4. Validate output
    5. Store in database
    """
    # Check for existing summary
    if not force_regenerate:
        existing_result = await session.execute(
            select(IncidentSummary)
            .where(IncidentSummary.incident_id == incident.id)
            .order_by(IncidentSummary.version.desc())
            .limit(1)
        )
        existing = existing_result.scalar_one_or_none()
        if existing:
            return existing

    # Build RCA bundle
    rca_bundle = await build_rca_bundle(session, incident)

    # Get next version number
    version_result = await session.execute(
        select(func.coalesce(func.max(IncidentSummary.version), 0))
        .where(IncidentSummary.incident_id == incident.id)
    )
    next_version = (version_result.scalar() or 0) + 1

    # Try AI generation
    summary_data = None
    model_used = None
    prompt_tokens = None
    completion_tokens = None
    gen_time_ms = None

    if generation_type == "ai_generated" and settings.summary_generation_enabled:
        try:
            start = time.monotonic()
            summary_data, model_used, prompt_tokens, completion_tokens = (
                await _generate_ai_summary(rca_bundle)
            )
            gen_time_ms = int((time.monotonic() - start) * 1000)
        except Exception as e:
            log.warning("ai_summary_failed", error=str(e), fallback="deterministic")
            generation_type = "deterministic"

    # Fallback to deterministic
    if summary_data is None:
        generation_type = "deterministic"
        summary_data = _generate_deterministic_summary(rca_bundle)

    # Validate
    validation_passed, validation_errors = _validate_summary(summary_data, rca_bundle)

    # Create summary record
    summary = IncidentSummary(
        id=uuid.uuid4(),
        incident_id=incident.id,
        version=next_version,
        generation_type=generation_type,
        executive_summary=summary_data.get("executive_summary", ""),
        root_cause=summary_data.get("root_cause"),
        observed_facts=summary_data.get("observed_facts"),
        recommended_actions=summary_data.get("recommended_actions"),
        confidence_notes=summary_data.get("confidence_notes"),
        model_used=model_used,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        generation_time_ms=gen_time_ms,
        validation_passed=validation_passed,
        validation_errors=validation_errors if not validation_passed else None,
        rca_bundle=rca_bundle,
    )

    session.add(summary)
    await session.flush()

    # Save to MemPalace for persistent memory
    await save_incident_to_palace(
        incident_id=str(incident.id),
        incident_number=incident.incident_number,
        classification=incident.classification,
        primary_src_ip=incident.primary_src_ip,
        summary_text=summary.executive_summary,
        mitre_techniques=incident.mitre_techniques,
    )

    log.info(
        "summary_generated",
        incident_id=str(incident.id),
        version=next_version,
        type=generation_type,
        validated=validation_passed,
    )

    return summary


async def _generate_ai_summary(
    rca_bundle: dict,
) -> tuple[dict, str, int, int]:
    """Call Mistral AI API to generate an AI summary."""
    from mistralai.client.sdk import Mistral

    client = Mistral(api_key=settings.mistral_api_key)

    # Inject MemPalace wake-up context if available
    wake_up_context = get_wake_up_context()
    system_prompt = SYSTEM_PROMPT
    if wake_up_context:
        system_prompt += f"\n\n## AEGIS Memory Context (MemPalace L0+L1)\n{wake_up_context}\n\nUse the above context to reference prior attacker behavior when relevant.\nIf an attacker IP has been seen before, say so explicitly."

    user_prompt = f"Generate an investigation summary for this incident:\n\n{json.dumps(rca_bundle, indent=2, default=str)}"

    response = await client.chat.complete_async(
        model=settings.mistral_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.3,
        max_tokens=1500,
        response_format={"type": "json_object"},
    )

    content = response.choices[0].message.content
    summary_data = json.loads(content)

    return (
        summary_data,
        response.model,
        response.usage.prompt_tokens if response.usage else 0,
        response.usage.completion_tokens if response.usage else 0,
    )


def _generate_deterministic_summary(rca_bundle: dict) -> dict:
    """Generate a template-based deterministic summary (fallback)."""
    incident = rca_bundle.get("incident", {})
    facts = rca_bundle.get("observed_facts", [])
    actions = rca_bundle.get("recommended_actions", [])
    timeline = rca_bundle.get("timeline", [])
    entities = rca_bundle.get("entities", {})
    mitre = rca_bundle.get("mitre_techniques", [])

    # Executive summary
    classification = incident.get("classification", "unknown")
    severity = incident.get("severity", "unknown")
    alert_count = incident.get("alert_count", 0)
    src_ips = entities.get("source_ips", [])
    hosts = entities.get("hosts", [])

    src_ip_str = src_ips[0] if src_ips else "unknown source"
    host_str = hosts[0] if hosts else "unknown host"

    class_labels = {
        "account_compromise": "account compromise",
        "malware_execution": "malware execution",
        "brute_force_attempt": "brute force attack",
        "reconnaissance": "reconnaissance activity",
        "privilege_escalation": "privilege escalation",
        "possible_exfiltration": "data exfiltration",
    }
    class_label = class_labels.get(classification, classification)

    exec_summary = (
        f"AEGIS correlated {alert_count} alert(s) into a {severity}-severity "
        f"{class_label} incident originating from {src_ip_str} targeting {host_str}. "
    )

    if timeline:
        first = timeline[0].get("description", "")
        last = timeline[-1].get("description", "")
        exec_summary += f"Activity ranged from '{first}' to '{last}'."

    # Technique summary
    tech_names = [t.get("name", t.get("id", "")) for t in mitre]
    if tech_names:
        exec_summary += f" MITRE techniques observed: {', '.join(tech_names)}."

    return {
        "executive_summary": exec_summary,
        "root_cause": rca_bundle.get("root_cause_hypothesis", ""),
        "observed_facts": facts,
        "recommended_actions": actions,
        "confidence_notes": (
            f"Based on {alert_count} correlated alerts with "
            f"{incident.get('confidence', 0):.0%} confidence."
        ),
    }


def _validate_summary(
    summary_data: dict, rca_bundle: dict
) -> tuple[bool, dict | None]:
    """
    Validate that the summary doesn't hallucinate entities.
    Returns (passed, errors_dict_or_None).
    """
    errors: dict[str, list[str]] = {}

    # Check required keys
    required_keys = ["executive_summary"]
    missing = [k for k in required_keys if k not in summary_data]
    if missing:
        errors["missing_keys"] = missing

    # Check for hallucinated IPs (IPs in summary not in bundle)
    entities = rca_bundle.get("entities", {})
    known_ips = set(entities.get("source_ips", [])) | set(entities.get("destination_ips", []))

    summary_text = json.dumps(summary_data, default=str)

    # Basic IP pattern check
    import re
    found_ips = set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', summary_text))
    hallucinated_ips = found_ips - known_ips - {"0.0.0.0", "127.0.0.1"}
    if hallucinated_ips:
        errors["hallucinated_ips"] = list(hallucinated_ips)

    passed = len(errors) == 0
    return passed, errors if errors else None
