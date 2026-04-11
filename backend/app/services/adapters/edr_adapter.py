"""
EDR Adapter — normalizes mock CrowdStrike EDR events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from dateutil.parser import isoparse

from app.services.adapters.base import BaseAdapter, CanonicalAlert


class EDRAdapter(BaseAdapter):
    """Handles crowdstrike_mock events: process_tree, malicious_hash, priv_esc, etc."""

    source_family = "edr"
    source_type = "crowdstrike_mock"

    EVENT_MAP = {
        "process_created": ("execution", "process_created", ["T1059"], "execution", "medium"),
        "malicious_hash": ("execution", "malicious_binary_detected", ["T1204"], "execution", "critical"),
        "privilege_escalation": ("endpoint", "privilege_escalation", ["T1548", "T1134"], "privilege-escalation", "critical"),
        "lateral_movement": ("network", "lateral_movement_attempt", ["T1021"], "lateral-movement", "high"),
        "persistence_created": ("endpoint", "persistence_created", ["T1543", "T1547"], "persistence", "high"),
        "persistence_crontab": ("endpoint", "persistence_crontab", ["T1543"], "persistence", "high"),
        "persistence_service": ("endpoint", "persistence_service", ["T1543", "T1547"], "persistence", "high"),
        "credential_dump": ("endpoint", "credential_dump", ["T1003"], "credential-access", "critical"),
        "encoded_command": ("execution", "encoded_command_execution", ["T1059", "T1027"], "execution", "high"),
        "dll_injection": ("execution", "dll_injection", ["T1055"], "defense-evasion", "critical"),
    }

    def normalize(self, raw_payload: dict[str, Any]) -> CanonicalAlert:
        event_type = raw_payload.get("event_type", "unknown")
        mapping = self.EVENT_MAP.get(event_type, (
            "endpoint", event_type, [], None, "medium"
        ))
        category, event_name, mitre_ids, tactic, severity = mapping

        severity = raw_payload.get("severity", severity)

        risk_flags = []
        if raw_payload.get("is_malicious"):
            risk_flags.append("malicious_hash_detected")
        if raw_payload.get("encoded"):
            risk_flags.append("encoded_execution")
        if raw_payload.get("privilege_level") == "SYSTEM":
            risk_flags.append("system_level_access")

        return CanonicalAlert(
            source_family=self.source_family,
            source_type=self.source_type,
            event_time=isoparse(raw_payload.get("timestamp", datetime.utcnow().isoformat())),
            category=category,
            event_name=event_name,
            severity=severity,
            confidence=float(raw_payload.get("confidence", 0.8)),
            user_name=raw_payload.get("user") or raw_payload.get("account_name"),
            host_name=raw_payload.get("host") or raw_payload.get("hostname"),
            source_ip=raw_payload.get("src_ip"),
            destination_ip=raw_payload.get("dst_ip"),
            mitre_technique_ids=mitre_ids,
            mitre_tactic=tactic,
            description=raw_payload.get("description", f"EDR event: {event_type}"),
            risk_flags=risk_flags,
            raw_command=raw_payload.get("command_line"),
            extra_data={
                "process_name": raw_payload.get("process_name"),
                "parent_process": raw_payload.get("parent_process"),
                "file_hash": raw_payload.get("file_hash"),
                "original_event_type": event_type,
            },
        )
