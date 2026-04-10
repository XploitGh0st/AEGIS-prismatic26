"""
BaseAdapter — abstract interface for source-specific normalization.

Every adapter transforms a raw payload into a CanonicalAlert dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class CanonicalAlert:
    """
    The canonical alert structure that all adapters produce.
    Maps 1:1 to the NormalizedAlert ORM model.
    """

    # ── Source ────────────────────────────────────────────
    source_family: str
    source_type: str

    # ── Canonical fields ─────────────────────────────────
    event_time: datetime
    category: str  # authentication, execution, network, endpoint
    event_name: str  # failed_login, command_execution, port_scan, ...
    severity: str  # low, medium, high, critical
    confidence: float = 0.5

    # ── Entity fields ────────────────────────────────────
    user_name: str | None = None
    host_name: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None

    # ── MITRE ATT&CK ────────────────────────────────────
    mitre_technique_ids: list[str] = field(default_factory=list)
    mitre_tactic: str | None = None

    # ── Extra context ────────────────────────────────────
    description: str | None = None
    risk_flags: list[str] = field(default_factory=list)
    raw_command: str | None = None
    session_id: str | None = None
    extra_data: dict[str, Any] | None = None


class BaseAdapter:
    """
    Abstract adapter interface. Subclass and implement normalize().

    Attributes:
        source_family: The family of source (siem, edr, ids, honeypot)
        source_type: The specific source within the family
    """

    source_family: str = ""
    source_type: str = ""

    def normalize(self, raw_payload: dict[str, Any]) -> CanonicalAlert:
        """
        Transform a raw payload into a CanonicalAlert.
        Must be implemented by each adapter subclass.
        """
        raise NotImplementedError(
            f"Adapter {self.__class__.__name__} must implement normalize()"
        )

    def can_handle(self, source_family: str, source_type: str) -> bool:
        """Check if this adapter can handle the given source."""
        return (
            self.source_family == source_family
            and self.source_type == source_type
        )
