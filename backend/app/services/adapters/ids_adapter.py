"""
IDS Adapter — normalizes mock Suricata IDS events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from dateutil.parser import isoparse

from app.services.adapters.base import BaseAdapter, CanonicalAlert


class IDSAdapter(BaseAdapter):
    """Handles suricata_mock events: port_scan, traffic_spike, signature_match, etc."""

    source_family = "ids"
    source_type = "suricata_mock"

    EVENT_MAP = {
        "port_scan": ("network", "port_scan_detected", ["T1046"], "reconnaissance", "medium"),
        "traffic_spike": ("network", "traffic_anomaly", ["T1498"], "impact", "medium"),
        "signature_match": ("network", "ids_signature_match", [], "initial-access", "high"),
        "dns_tunnel": ("network", "dns_tunnel_detected", ["T1071"], "command-and-control", "high"),
        "ssh_brute_force": ("authentication", "ssh_brute_force", ["T1110"], "credential-access", "high"),
        "outbound_c2": ("network", "outbound_c2_beacon", ["T1071", "T1573"], "command-and-control", "critical"),
        "exploit_attempt": ("network", "exploit_attempt", ["T1190"], "initial-access", "critical"),
        "web_exploit": ("execution", "web_exploit_attempt", ["T1190"], "initial-access", "high"),
        "suspicious_download": ("execution", "suspicious_download", ["T1105"], "command-and-control", "high"),
        "service_probe": ("network", "service_probe", ["T1046"], "reconnaissance", "low"),
        "protocol_anomaly": ("network", "protocol_anomaly", [], "defense-evasion", "low"),
    }

    def normalize(self, raw_payload: dict[str, Any]) -> CanonicalAlert:
        event_type = raw_payload.get("event_type", raw_payload.get("alert_type", "unknown"))
        mapping = self.EVENT_MAP.get(event_type, (
            "network", event_type, [], None, "medium"
        ))
        category, event_name, mitre_ids, tactic, severity = mapping

        severity = raw_payload.get("severity", severity)

        return CanonicalAlert(
            source_family=self.source_family,
            source_type=self.source_type,
            event_time=isoparse(raw_payload.get("timestamp", datetime.utcnow().isoformat())),
            category=category,
            event_name=event_name,
            severity=severity,
            confidence=float(raw_payload.get("confidence", 0.6)),
            source_ip=raw_payload.get("src_ip") or raw_payload.get("source_ip"),
            destination_ip=raw_payload.get("dst_ip") or raw_payload.get("dest_ip"),
            source_port=raw_payload.get("src_port"),
            destination_port=raw_payload.get("dst_port"),
            host_name=raw_payload.get("sensor") or raw_payload.get("hostname"),
            mitre_technique_ids=mitre_ids,
            mitre_tactic=tactic,
            description=raw_payload.get("description", f"IDS event: {event_type}"),
            extra_data={
                "signature_id": raw_payload.get("signature_id"),
                "signature_name": raw_payload.get("signature_name"),
                "protocol": raw_payload.get("protocol"),
                "bytes_in": raw_payload.get("bytes_in"),
                "bytes_out": raw_payload.get("bytes_out"),
                "original_event_type": event_type,
            },
        )
