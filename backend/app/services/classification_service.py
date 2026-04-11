"""
Classification Service — determines the incident type based on alert composition.

7 incident types in precedence order:
1. cve_exploitation — active exploitation of public-facing apps, java deserialization
2. account_compromise — failed login burst + success + post-auth activity
3. malware_execution — suspicious process tree, encoded commands, malicious hash
4. privilege_escalation — admin group change, token elevation
5. possible_exfiltration — outbound spike, suspicious external transfer
6. brute_force_attempt — repeated failed logins, no success
7. reconnaissance — port scan, service probing
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.incident import Incident


def classify_incident(incident: "Incident") -> str:
    """
    Classify the incident type based on aggregated techniques, tactics,
    and alert composition. Returns the highest-precedence matching type.
    """
    techniques = set(incident.mitre_techniques or [])
    tactics = set(incident.mitre_tactics or [])

    # ── 0. CVE Exploitation (Highest Precedence) ─────────
    # Public-Facing App Exploit (T1190) or Client Exploit (T1203)
    has_exploit = bool(techniques & {"T1190", "T1203", "T1659"})
    has_execution = bool(techniques & {"T1059", "T1204", "T1053"})
    has_c2 = "T1071" in techniques or "T1573" in techniques
    
    if has_exploit and (has_execution or has_c2):
        return "cve_exploitation"

    # ── 1. Account Compromise ────────────────────────────
    # Brute force (T1110) + Valid Accounts (T1078) + execution
    has_brute = "T1110" in techniques
    has_valid_accounts = "T1078" in techniques
    has_file_transfer = "T1105" in techniques

    if has_valid_accounts and (has_brute or has_execution or has_file_transfer):
        return "account_compromise"

    # ── 2. Malware Execution ─────────────────────────────
    has_malware_indicators = bool(techniques & {"T1204", "T1055", "T1027"})
    has_command_exec = "T1059" in techniques and has_file_transfer

    if has_malware_indicators or has_command_exec:
        return "malware_execution"

    # ── 3. Privilege Escalation ──────────────────────────
    has_privesc = bool(techniques & {"T1548", "T1134", "T1068"})
    if has_privesc:
        return "privilege_escalation"

    # ── 4. Possible Exfiltration ─────────────────────────
    has_exfil = bool(techniques & {"T1041", "T1048", "T1567"})
    if has_exfil:
        return "possible_exfiltration"

    # ── 5. Brute Force Attempt ───────────────────────────
    if has_brute and not has_valid_accounts:
        return "brute_force_attempt"

    # ── 6. Reconnaissance ────────────────────────────────
    has_recon = bool(techniques & {"T1046", "T1592", "T1595"})
    if has_recon:
        return "reconnaissance"

    # Default fallback
    if "credential-access" in tactics:
        return "brute_force_attempt"
    if "execution" in tactics:
        return "malware_execution"
    if "reconnaissance" in tactics:
        return "reconnaissance"

    return "reconnaissance"

