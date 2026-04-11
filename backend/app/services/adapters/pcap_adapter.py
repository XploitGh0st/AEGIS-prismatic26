"""
PCAP Adapter — normalizes PCAP analysis findings into CanonicalAlert objects.

Handles two paths:
1. Direct PCAP service output (has event_name, severity, etc.)
2. Scenario/mock payloads (has event_type, timestamp, etc.)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from dateutil.parser import isoparse

from app.services.adapters.base import BaseAdapter, CanonicalAlert


class PcapAdapter(BaseAdapter):
    """
    Adapter for PCAP-derived alerts (source_family=ids, source_type=pcap_analysis).

    The PCAP analysis service generates CanonicalAlert objects directly.
    When those alerts are ingested through the standard pipeline
    (as raw_alert payloads), this adapter normalizes them back.

    Also handles scenario/mock payloads with event_type field.
    """

    source_family = "ids"
    source_type = "pcap_analysis"

    # Map event_type (from scenarios/mock data) to canonical fields
    EVENT_MAP = {
        "jndi_injection": ("network", "jndi_injection", ["T1190", "T1059"], "initial_access", "critical"),
        "cve_exploit": ("execution", "cve_exploit", ["T1190", "T1203"], "initial_access", "critical"),
        "malicious_naming_service": ("network", "malicious_naming_service", ["T1071", "T1203"], "execution", "critical"),
        "java_deserialization": ("execution", "java_deserialization", ["T1203", "T1059"], "execution", "critical"),
        "suspicious_payload": ("execution", "suspicious_payload", ["T1059"], "execution", "high"),
        "c2_beaconing": ("network", "c2_beaconing", ["T1071", "T1573"], "command_and_control", "high"),
        "port_scan": ("network", "port_scan_detected", ["T1046"], "reconnaissance", "medium"),
        "dns_anomaly": ("network", "dns_anomaly", ["T1071"], "command_and_control", "medium"),
        "data_exfiltration": ("network", "data_exfiltration", ["T1041"], "exfiltration", "critical"),
        "service_probe": ("network", "service_probe", ["T1046"], "reconnaissance", "low"),
        "web_exploit": ("execution", "web_exploit", ["T1190"], "initial_access", "high"),
        "suspicious_download": ("execution", "suspicious_download", ["T1105"], "command_and_control", "high"),
        "traffic_summary": ("network", "traffic_summary", [], "", "low"),
    }

    def normalize(self, raw_payload: dict[str, Any]) -> CanonicalAlert:
        """Transform a PCAP analysis payload into a CanonicalAlert."""

        # Determine if this is a direct PCAP service payload or scenario payload
        event_type = raw_payload.get("event_type")

        if event_type and event_type in self.EVENT_MAP:
            # Scenario/mock payload path — map event_type to canonical fields
            category, event_name, mitre_ids, tactic, default_severity = self.EVENT_MAP[event_type]

            # Allow scenario to override MITRE techniques
            mitre_ids = raw_payload.get("mitre_technique_ids", mitre_ids)

            return CanonicalAlert(
                source_family="ids",
                source_type="pcap_analysis",
                event_time=isoparse(raw_payload.get("timestamp", raw_payload.get("event_time", datetime.utcnow().isoformat()))),
                category=category,
                event_name=event_name,
                severity=raw_payload.get("severity", default_severity),
                confidence=float(raw_payload.get("confidence", 0.75)),
                source_ip=raw_payload.get("src_ip") or raw_payload.get("source_ip"),
                destination_ip=raw_payload.get("dst_ip") or raw_payload.get("destination_ip"),
                source_port=raw_payload.get("src_port") or raw_payload.get("source_port"),
                destination_port=raw_payload.get("dst_port") or raw_payload.get("destination_port"),
                mitre_technique_ids=mitre_ids,
                mitre_tactic=tactic,
                description=raw_payload.get("description", f"PCAP finding: {event_type}"),
                risk_flags=raw_payload.get("risk_flags", []),
                session_id=raw_payload.get("session_id"),
                extra_data={k: v for k, v in raw_payload.items() if k not in {
                    "event_type", "timestamp", "event_time", "src_ip", "dst_ip",
                    "src_port", "dst_port", "description", "severity", "confidence",
                    "source_ip", "destination_ip", "source_port", "destination_port",
                    "mitre_technique_ids", "mitre_tactic", "risk_flags", "session_id",
                }},
            )

        # Direct PCAP service output path — fields already in canonical format
        return CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=isoparse(raw_payload.get("event_time", raw_payload.get("timestamp", datetime.utcnow().isoformat()))),
            category=raw_payload.get("category", "network"),
            event_name=raw_payload.get("event_name", "pcap_finding"),
            severity=raw_payload.get("severity", "medium"),
            confidence=float(raw_payload.get("confidence", 0.6)),
            user_name=raw_payload.get("user_name"),
            host_name=raw_payload.get("host_name"),
            source_ip=raw_payload.get("source_ip"),
            destination_ip=raw_payload.get("destination_ip"),
            source_port=raw_payload.get("source_port"),
            destination_port=raw_payload.get("destination_port"),
            mitre_technique_ids=raw_payload.get("mitre_technique_ids", []),
            mitre_tactic=raw_payload.get("mitre_tactic"),
            description=raw_payload.get("description"),
            risk_flags=raw_payload.get("risk_flags", []),
            raw_command=raw_payload.get("raw_command"),
            session_id=raw_payload.get("session_id"),
            extra_data=raw_payload.get("extra_data"),
        )
