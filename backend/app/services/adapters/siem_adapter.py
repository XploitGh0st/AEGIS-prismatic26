"""
SIEM Adapter — normalizes mock Splunk SIEM events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from dateutil.parser import isoparse

from app.services.adapters.base import BaseAdapter, CanonicalAlert


class SIEMAdapter(BaseAdapter):
    """Handles splunk_mock events: failed_login, success_login, suspicious_process, etc."""

    source_family = "siem"
    source_type = "splunk_mock"

    # Event type → (category, event_name, mitre_ids, tactic, severity)
    EVENT_MAP = {
        "failed_login": ("authentication", "failed_login", ["T1110"], "credential-access", "medium"),
        "success_login": ("authentication", "successful_login", ["T1078"], "initial-access", "high"),
        "suspicious_process": ("execution", "suspicious_process", ["T1059"], "execution", "high"),
        "privilege_escalation": ("endpoint", "privilege_escalation", ["T1548"], "privilege-escalation", "critical"),
        "account_lockout": ("authentication", "account_lockout", ["T1110"], "credential-access", "medium"),
        "service_created": ("endpoint", "service_created", ["T1543"], "persistence", "high"),
        "firewall_block": ("network", "firewall_block", [], "defense-evasion", "low"),
        "data_exfiltration": ("network", "data_exfiltration", ["T1041"], "exfiltration", "critical"),
        "dns_query_suspicious": ("network", "dns_query_suspicious", ["T1071"], "command-and-control", "medium"),
    }

    def normalize(self, raw_payload: dict[str, Any]) -> CanonicalAlert:
        event_type = raw_payload.get("event_type", "unknown")
        mapping = self.EVENT_MAP.get(event_type, (
            "unknown", event_type, [], None, "medium"
        ))
        category, event_name, mitre_ids, tactic, severity = mapping

        # Override severity if payload specifies it
        severity = raw_payload.get("severity", severity)

        return CanonicalAlert(
            source_family=self.source_family,
            source_type=self.source_type,
            event_time=isoparse(raw_payload.get("timestamp", datetime.utcnow().isoformat())),
            category=category,
            event_name=event_name,
            severity=severity,
            confidence=float(raw_payload.get("confidence", 0.7)),
            user_name=raw_payload.get("user") or raw_payload.get("username"),
            host_name=raw_payload.get("host") or raw_payload.get("hostname"),
            source_ip=raw_payload.get("src_ip") or raw_payload.get("source_ip"),
            destination_ip=raw_payload.get("dst_ip") or raw_payload.get("dest_ip"),
            source_port=raw_payload.get("src_port"),
            destination_port=raw_payload.get("dst_port"),
            mitre_technique_ids=mitre_ids,
            mitre_tactic=tactic,
            description=raw_payload.get("description", f"SIEM event: {event_type}"),
            extra_data={
                "original_event_type": event_type,
                "raw_fields": {k: v for k, v in raw_payload.items()
                              if k not in ("timestamp", "event_type")},
            },
        )
