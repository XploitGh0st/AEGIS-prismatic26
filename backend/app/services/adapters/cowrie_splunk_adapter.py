"""
Cowrie-Splunk Adapter — normalizes real Cowrie honeypot events from Splunk.

This is the primary adapter for AEGIS live data. It maps Cowrie eventid values
to the AEGIS canonical schema with MITRE ATT&CK mappings and smart command analysis.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from dateutil.parser import isoparse

from app.services.adapters.base import BaseAdapter, CanonicalAlert


# ── High-risk command patterns for severity boosting ────────────
HIGH_RISK_COMMANDS: list[str] = [
    "wget", "curl", "tftp",                    # download tools
    "chmod +x", "chmod 777",                    # making files executable
    "/tmp/", "/dev/shm/",                       # suspicious paths
    "base64", "python -c", "perl -e",           # encoded execution
    "iptables", "ufw",                          # firewall manipulation
    "passwd", "useradd", "usermod",             # account manipulation
    "cat /etc/passwd", "cat /etc/shadow",       # credential harvesting
    "nmap", "masscan",                          # scanning from honeypot
    "rm -rf", "dd if=",                         # destructive commands
    "nc ", "netcat", "ncat",                    # reverse shells
    "ssh ", "scp ",                             # lateral movement
    "crontab", "/etc/cron",                     # persistence
    ".ssh/authorized_keys",                     # persistence via SSH keys
    "history -c", "unset HISTFILE",             # anti-forensics
]

# Patterns → risk flag labels
COMMAND_RISK_FLAGS: dict[str, list[str]] = {
    "wget": ["suspicious_download"],
    "curl": ["suspicious_download"],
    "tftp": ["suspicious_download"],
    "chmod +x": ["file_made_executable"],
    "chmod 777": ["file_made_executable"],
    "cat /etc/passwd": ["credential_harvesting"],
    "cat /etc/shadow": ["credential_harvesting"],
    "passwd": ["account_manipulation"],
    "useradd": ["account_manipulation"],
    "usermod": ["account_manipulation"],
    "nmap": ["lateral_movement_attempt"],
    "masscan": ["lateral_movement_attempt"],
    "ssh ": ["lateral_movement_attempt"],
    "scp ": ["lateral_movement_attempt"],
    "nc ": ["reverse_shell_attempt"],
    "netcat": ["reverse_shell_attempt"],
    "base64": ["encoded_execution"],
    "python -c": ["encoded_execution"],
    "perl -e": ["encoded_execution"],
    "crontab": ["persistence_attempt"],
    "/etc/cron": ["persistence_attempt"],
    ".ssh/authorized_keys": ["persistence_attempt"],
    "rm -rf": ["destructive_command"],
    "dd if=": ["destructive_command"],
    "history -c": ["anti_forensics"],
    "unset HISTFILE": ["anti_forensics"],
    "iptables": ["firewall_manipulation"],
    "ufw": ["firewall_manipulation"],
}


class CowrieSplunkAdapter(BaseAdapter):
    """
    Normalizes Cowrie SSH/Telnet honeypot events (received via Splunk or directly).

    Maps Cowrie eventid values to AEGIS canonical fields with:
    - MITRE ATT&CK technique/tactic mappings
    - Smart command analysis with high-risk detection
    - Session-based correlation support
    """

    source_family = "siem"
    source_type = "cowrie_splunk"

    # eventid → (category, event_name, mitre_ids, tactic, base_severity)
    EVENTID_MAP: dict[str, tuple[str, str, list[str], str, str]] = {
        "cowrie.session.connect": (
            "network", "ssh_connection_attempt", ["T1046"], "reconnaissance", "low"
        ),
        "cowrie.login.failed": (
            "authentication", "failed_login", ["T1110"], "credential-access", "medium"
        ),
        "cowrie.login.success": (
            "authentication", "successful_login", ["T1078"], "initial-access", "high"
        ),
        "cowrie.command.input": (
            "execution", "command_execution", ["T1059"], "execution", "high"
        ),
        "cowrie.command.failed": (
            "execution", "command_execution_failed", ["T1059"], "execution", "medium"
        ),
        "cowrie.session.file_download": (
            "execution", "file_download", ["T1105"], "command-and-control", "critical"
        ),
        "cowrie.session.file_upload": (
            "execution", "file_upload", ["T1105"], "command-and-control", "high"
        ),
        "cowrie.direct-tcpip.request": (
            "network", "tunnel_request", ["T1572"], "command-and-control", "high"
        ),
        "cowrie.client.version": (
            "network", "client_fingerprint", [], "reconnaissance", "low"
        ),
        "cowrie.session.closed": (
            "network", "session_closed", [], None, "low"
        ),
        "cowrie.client.kex": (
            "network", "key_exchange", [], "reconnaissance", "low"
        ),
        "cowrie.log.closed": (
            "network", "log_closed", [], None, "low"
        ),
    }

    def normalize(self, raw_payload: dict[str, Any]) -> CanonicalAlert:
        """Transform a Cowrie JSON event into a CanonicalAlert."""
        eventid = raw_payload.get("eventid", "unknown")

        # Get base mapping for this event type
        mapping = self.EVENTID_MAP.get(eventid, (
            "network", eventid, [], None, "medium"
        ))
        category, event_name, mitre_ids, tactic, severity = mapping

        # Parse event time
        event_time = self._parse_time(raw_payload)

        # Extract entities
        src_ip = raw_payload.get("src_ip")
        session_id = raw_payload.get("session")
        user_name = raw_payload.get("username")
        host_name = raw_payload.get("sensor", "honeypot")
        dst_ip = raw_payload.get("dst_ip")
        src_port = raw_payload.get("src_port")
        dst_port = raw_payload.get("dst_port")

        # Initialize risk flags and description
        risk_flags: list[str] = []
        description = f"Cowrie {eventid}"
        raw_command: str | None = None
        confidence = 0.9  # Honeypot data is high-confidence (it's always malicious)

        # ── Smart command analysis ───────────────────────
        if eventid == "cowrie.command.input":
            raw_command = raw_payload.get("input", "")
            description = f"Command executed: {raw_command}"
            severity, risk_flags = self._analyze_command(raw_command, severity)

        elif eventid == "cowrie.login.failed":
            password = raw_payload.get("password", "")
            description = f"Failed SSH login: user={user_name} pass={password}"

        elif eventid == "cowrie.login.success":
            password = raw_payload.get("password", "")
            description = f"Successful SSH login: user={user_name} pass={password}"
            risk_flags.append("honeypot_login_success")

        elif eventid == "cowrie.session.file_download":
            url = raw_payload.get("url", "")
            shasum = raw_payload.get("shasum", "")
            description = f"File downloaded: {url} (SHA: {shasum[:16]}...)"
            risk_flags.append("suspicious_download")
            risk_flags.append("malware_candidate")

        elif eventid == "cowrie.session.file_upload":
            description = "File uploaded to honeypot"
            risk_flags.append("file_upload")

        elif eventid == "cowrie.direct-tcpip.request":
            description = f"TCP tunnel request from {src_ip}"
            risk_flags.append("tunnel_attempt")

        elif eventid == "cowrie.client.version":
            version = raw_payload.get("version", "")
            description = f"SSH client version: {version}"

        # Build extra data
        extra_data = {
            "eventid": eventid,
            "protocol": raw_payload.get("protocol", "ssh"),
        }
        if raw_payload.get("password"):
            extra_data["password_used"] = raw_payload["password"]
        if raw_payload.get("url"):
            extra_data["download_url"] = raw_payload["url"]
        if raw_payload.get("shasum"):
            extra_data["file_sha256"] = raw_payload["shasum"]
        if raw_payload.get("version"):
            extra_data["client_version"] = raw_payload["version"]

        return CanonicalAlert(
            source_family=self.source_family,
            source_type=self.source_type,
            event_time=event_time,
            category=category,
            event_name=event_name,
            severity=severity,
            confidence=confidence,
            user_name=user_name,
            host_name=host_name,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            mitre_technique_ids=list(mitre_ids),  # copy
            mitre_tactic=tactic,
            description=description,
            risk_flags=risk_flags,
            raw_command=raw_command,
            session_id=session_id,
            extra_data=extra_data,
        )

    def _parse_time(self, payload: dict[str, Any]) -> datetime:
        """Parse Cowrie timestamp string to datetime."""
        ts = payload.get("timestamp")
        if ts:
            try:
                return isoparse(ts)
            except (ValueError, TypeError):
                pass
        return datetime.utcnow()

    def _analyze_command(
        self, command: str, base_severity: str
    ) -> tuple[str, list[str]]:
        """
        Analyze a Cowrie command for high-risk patterns.
        Returns (possibly upgraded severity, risk_flags list).
        """
        risk_flags: list[str] = []
        cmd_lower = command.lower()
        severity = base_severity

        for pattern, flags in COMMAND_RISK_FLAGS.items():
            if pattern in cmd_lower:
                risk_flags.extend(flags)

        # Severity upgrade based on risk flags
        critical_flags = {
            "suspicious_download", "reverse_shell_attempt",
            "credential_harvesting", "destructive_command",
        }
        high_flags = {
            "file_made_executable", "persistence_attempt",
            "account_manipulation", "lateral_movement_attempt",
            "encoded_execution", "firewall_manipulation",
        }

        if risk_flags:
            has_critical = bool(critical_flags & set(risk_flags))
            has_high = bool(high_flags & set(risk_flags))

            if has_critical:
                severity = "critical"
            elif has_high and severity in ("low", "medium"):
                severity = "high"

        # Deduplicate flags
        risk_flags = list(dict.fromkeys(risk_flags))

        return severity, risk_flags
