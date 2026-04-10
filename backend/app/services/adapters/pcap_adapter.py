"""
PCAP Adapter — normalizes PCAP analysis findings into CanonicalAlert objects.

Since the PCAP service already generates CanonicalAlert objects directly,
this adapter handles the reverse path: converting CanonicalAlert data
back into the ingest format for the pipeline.
"""

from __future__ import annotations

from typing import Any

from app.services.adapters.base import BaseAdapter, CanonicalAlert


class PcapAdapter(BaseAdapter):
    """
    Adapter for PCAP-derived alerts.

    The PCAP analysis service generates CanonicalAlert objects directly,
    but when those alerts are ingested through the standard pipeline
    (as raw_alert payloads), this adapter normalizes them back.
    """

    source_family = "ids"
    source_type = "pcap_analysis"

    def normalize(self, raw_payload: dict[str, Any]) -> CanonicalAlert:
        """Transform a PCAP analysis payload into a CanonicalAlert."""
        from app.utils.datetime import parse_iso

        return CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=parse_iso(raw_payload.get("event_time", "")),
            category=raw_payload.get("category", "network"),
            event_name=raw_payload.get("event_name", "pcap_finding"),
            severity=raw_payload.get("severity", "medium"),
            confidence=raw_payload.get("confidence", 0.6),
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
