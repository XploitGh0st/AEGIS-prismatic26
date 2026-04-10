"""
PCAP Analysis Service — parses PCAP files and extracts security-relevant events.

Uses scapy to parse packet captures and generates CanonicalAlert objects that
feed directly into the AEGIS normalization → correlation → scoring pipeline.

Capabilities:
- TCP session reconstruction
- DNS query analysis (DGA detection, tunneling indicators)
- Port scan detection (SYN scan, connect scan)
- SSH traffic analysis (brute force patterns)
- HTTP request inspection (suspicious URIs, downloads)
- Payload anomaly detection (encoded commands, shell patterns)
- Traffic volume analysis
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.adapters.base import CanonicalAlert

log = get_logger("pcap")
settings = get_settings()

# ── Suspicious patterns ─────────────────────────────────
SUSPICIOUS_PAYLOAD_PATTERNS = [
    b"wget ", b"curl ", b"/bin/sh", b"/bin/bash",
    b"chmod +x", b"chmod 777", b"python -c",
    b"base64", b"eval(", b"exec(",
    b"/etc/passwd", b"/etc/shadow",
    b"nc -e", b"ncat ", b"netcat",
    b"powershell", b"cmd.exe",
    b"<script", b"javascript:",
    b"rm -rf", b"dd if=",
]

SUSPICIOUS_DNS_TLDS = {
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".club", ".work", ".info",
}

COMMON_SCAN_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 9200, 27017,
}


def _ensure_upload_dir() -> Path:
    """Ensure the PCAP upload directory exists."""
    upload_dir = Path(settings.pcap_upload_dir).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


async def save_uploaded_pcap(filename: str, content: bytes) -> str:
    """Save an uploaded PCAP file and return the file path."""
    upload_dir = _ensure_upload_dir()
    pcap_id = hashlib.sha256(f"{filename}{len(content)}{uuid.uuid4()}".encode()).hexdigest()[:16]
    safe_name = f"{pcap_id}_{filename.replace(' ', '_')}"
    file_path = upload_dir / safe_name
    file_path.write_bytes(content)
    log.info("pcap_saved", pcap_id=pcap_id, filename=filename, size=len(content))
    return str(file_path), pcap_id


def analyze_pcap(file_path: str) -> list[CanonicalAlert]:
    """
    Analyze a PCAP file and return a list of CanonicalAlert objects.

    Analysis pipeline:
    1. Read packets from PCAP
    2. Reconstruct TCP sessions
    3. Detect port scanning patterns
    4. Analyze DNS queries
    5. Inspect payloads for suspicious content
    6. Detect SSH brute force patterns
    7. Analyze HTTP traffic
    8. Generate alerts for each finding
    """
    try:
        # Import scapy here to avoid startup cost
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
    except ImportError:
        log.error("scapy_not_installed")
        raise RuntimeError("scapy is required for PCAP analysis. Install with: pip install scapy")

    log.info("pcap_analysis_start", file=file_path)
    alerts: list[CanonicalAlert] = []

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        log.error("pcap_read_error", error=str(e))
        raise RuntimeError(f"Failed to read PCAP file: {e}")

    total_packets = len(packets)
    log.info("pcap_packets_loaded", count=total_packets)

    # ── Data collection pass ─────────────────────────────
    tcp_sessions: dict[str, list] = defaultdict(list)
    dns_queries: list[dict] = []
    src_port_map: dict[str, set] = defaultdict(set)  # src_ip → set of dst_ports
    ssh_attempts: dict[str, list] = defaultdict(list)  # src_ip → list of timestamps
    http_requests: list[dict] = []
    suspicious_payloads: list[dict] = []

    # Per-IP traffic stats
    ip_bytes_sent: dict[str, int] = Counter()
    ip_bytes_recv: dict[str, int] = Counter()
    ip_connections: dict[str, int] = Counter()

    pcap_start_time = None
    pcap_end_time = None

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_time = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)

        # Track time range
        if pcap_start_time is None or pkt_time < pcap_start_time:
            pcap_start_time = pkt_time
        if pcap_end_time is None or pkt_time > pcap_end_time:
            pcap_end_time = pkt_time

        # Traffic stats
        pkt_size = len(pkt)
        ip_bytes_sent[src_ip] += pkt_size
        ip_bytes_recv[dst_ip] += pkt_size
        ip_connections[src_ip] += 1

        # ── TCP analysis ─────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            session_key = f"{src_ip}:{tcp.sport}->{dst_ip}:{tcp.dport}"
            tcp_sessions[session_key].append(pkt)

            # Track destination ports per source (for scan detection)
            src_port_map[src_ip].add(tcp.dport)

            # SSH traffic (port 22)
            if tcp.dport == 22 and tcp.flags & 0x02:  # SYN flag
                ssh_attempts[src_ip].append(pkt_time)

            # HTTP traffic
            if tcp.dport in (80, 8080, 8443) or tcp.sport in (80, 8080, 8443):
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    if payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"PUT "):
                        try:
                            first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
                            http_requests.append({
                                "time": pkt_time,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "request": first_line,
                                "size": len(payload),
                            })
                        except Exception:
                            pass

            # Payload inspection
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                for pattern in SUSPICIOUS_PAYLOAD_PATTERNS:
                    if pattern in payload:
                        suspicious_payloads.append({
                            "time": pkt_time,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "pattern": pattern.decode("utf-8", errors="replace"),
                            "payload_preview": payload[:200].decode("utf-8", errors="replace"),
                        })
                        break  # One alert per packet

        # ── DNS analysis ─────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                dns_queries.append({
                    "time": pkt_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "query": qname,
                    "qtype": pkt[DNSQR].qtype,
                })
            except Exception:
                pass

    # ── Alert Generation ─────────────────────────────────

    # Use pcap_start_time or now as base
    base_time = pcap_start_time or datetime.now(timezone.utc)

    # 1. Port Scan Detection
    for src_ip, ports in src_port_map.items():
        if len(ports) >= 10:
            scanned_common = ports & COMMON_SCAN_PORTS
            severity = "high" if len(ports) >= 50 else "medium"

            alerts.append(CanonicalAlert(
                source_family="ids",
                source_type="pcap_analysis",
                event_time=base_time,
                category="network",
                event_name="port_scan",
                severity=severity,
                confidence=min(0.95, 0.5 + len(ports) * 0.01),
                source_ip=src_ip,
                description=f"Port scan detected: {len(ports)} unique destination ports probed ({len(scanned_common)} common service ports)",
                mitre_technique_ids=["T1046"],
                mitre_tactic="discovery",
                risk_flags=["port_scan", "reconnaissance"],
                extra_data={
                    "ports_scanned": len(ports),
                    "common_ports_hit": list(scanned_common)[:20],
                    "sample_ports": sorted(list(ports))[:30],
                },
            ))

    # 2. SSH Brute Force Detection
    for src_ip, timestamps in ssh_attempts.items():
        if len(timestamps) >= 5:
            severity = "high" if len(timestamps) >= 20 else "medium"
            time_span = (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0

            alerts.append(CanonicalAlert(
                source_family="ids",
                source_type="pcap_analysis",
                event_time=min(timestamps),
                category="authentication",
                event_name="failed_login",
                severity=severity,
                confidence=min(0.95, 0.6 + len(timestamps) * 0.02),
                source_ip=src_ip,
                destination_port=22,
                description=f"SSH brute force attempt: {len(timestamps)} connection attempts in {time_span:.0f}s",
                mitre_technique_ids=["T1110"],
                mitre_tactic="credential_access",
                risk_flags=["brute_force", "ssh_attack"],
                extra_data={
                    "attempt_count": len(timestamps),
                    "time_span_seconds": time_span,
                    "attempts_per_second": len(timestamps) / max(time_span, 1),
                },
            ))

    # 3. DNS Anomaly Detection
    dns_domains = [q["query"] for q in dns_queries]
    domain_counter = Counter(dns_domains)

    # Check for DGA-like domains
    for query_data in dns_queries:
        domain = query_data["query"]
        # DGA heuristic: long random-looking subdomains
        parts = domain.split(".")
        if len(parts) >= 2:
            subdomain = parts[0]
            tld = "." + parts[-1] if len(parts[-1]) <= 4 else ""

            is_suspicious = False
            reasons = []

            # Long random subdomain
            if len(subdomain) > 20:
                is_suspicious = True
                reasons.append("long_subdomain")

            # High entropy (many unique chars relative to length)
            if len(subdomain) > 8:
                unique_ratio = len(set(subdomain)) / len(subdomain)
                if unique_ratio > 0.7:
                    is_suspicious = True
                    reasons.append("high_entropy")

            # Suspicious TLD
            if tld in SUSPICIOUS_DNS_TLDS:
                is_suspicious = True
                reasons.append("suspicious_tld")

            if is_suspicious:
                alerts.append(CanonicalAlert(
                    source_family="ids",
                    source_type="pcap_analysis",
                    event_time=query_data["time"],
                    category="network",
                    event_name="dns_anomaly",
                    severity="medium",
                    confidence=0.6,
                    source_ip=query_data["src_ip"],
                    description=f"Suspicious DNS query: {domain} (indicators: {', '.join(reasons)})",
                    mitre_technique_ids=["T1071"],
                    mitre_tactic="command_and_control",
                    risk_flags=["dns_anomaly"] + reasons,
                    extra_data={
                        "domain": domain,
                        "reasons": reasons,
                    },
                ))

    # DNS tunneling detection (high query volume to single domain)
    for domain, count in domain_counter.items():
        if count >= 50:
            alerts.append(CanonicalAlert(
                source_family="ids",
                source_type="pcap_analysis",
                event_time=base_time,
                category="network",
                event_name="dns_tunneling",
                severity="high",
                confidence=0.7,
                description=f"Possible DNS tunneling: {count} queries to {domain}",
                mitre_technique_ids=["T1572"],
                mitre_tactic="command_and_control",
                risk_flags=["dns_tunneling"],
                extra_data={"domain": domain, "query_count": count},
            ))

    # 4. Suspicious Payload Alerts
    for payload_info in suspicious_payloads:
        alerts.append(CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=payload_info["time"],
            category="execution",
            event_name="command_execution",
            severity="high",
            confidence=0.75,
            source_ip=payload_info["src_ip"],
            destination_ip=payload_info["dst_ip"],
            source_port=payload_info["src_port"],
            destination_port=payload_info["dst_port"],
            description=f"Suspicious payload pattern detected: {payload_info['pattern']}",
            mitre_technique_ids=["T1059"],
            mitre_tactic="execution",
            risk_flags=["suspicious_payload", "possible_exploit"],
            raw_command=payload_info["payload_preview"][:500],
            extra_data={
                "pattern_matched": payload_info["pattern"],
            },
        ))

    # 5. HTTP Suspicious Request Detection
    suspicious_http_patterns = [
        "/etc/passwd", "/etc/shadow", "/admin", "/wp-admin",
        "cmd=", "exec=", "shell", "../", "%2e%2e",
        ".php?", "union+select", "script>",
    ]

    for req in http_requests:
        request_lower = req["request"].lower()
        for pattern in suspicious_http_patterns:
            if pattern in request_lower:
                alerts.append(CanonicalAlert(
                    source_family="ids",
                    source_type="pcap_analysis",
                    event_time=req["time"],
                    category="network",
                    event_name="http_suspicious",
                    severity="high",
                    confidence=0.7,
                    source_ip=req["src_ip"],
                    destination_ip=req["dst_ip"],
                    description=f"Suspicious HTTP request: {req['request'][:200]}",
                    mitre_technique_ids=["T1190"],
                    mitre_tactic="initial_access",
                    risk_flags=["web_attack", "suspicious_http"],
                    raw_command=req["request"],
                ))
                break

    # 6. Large data transfer detection (possible exfiltration)
    for src_ip, total_bytes in ip_bytes_sent.items():
        if total_bytes > 10_000_000:  # >10MB sent
            alerts.append(CanonicalAlert(
                source_family="ids",
                source_type="pcap_analysis",
                event_time=base_time,
                category="network",
                event_name="large_transfer",
                severity="medium",
                confidence=0.5,
                source_ip=src_ip,
                description=f"Large outbound data transfer: {total_bytes / 1_000_000:.1f}MB from {src_ip}",
                mitre_technique_ids=["T1041"],
                mitre_tactic="exfiltration",
                risk_flags=["large_transfer", "possible_exfiltration"],
                extra_data={
                    "bytes_sent": total_bytes,
                    "mb_sent": round(total_bytes / 1_000_000, 2),
                },
            ))

    # 7. Generate a traffic summary alert
    if total_packets > 0:
        unique_src_ips = set()
        unique_dst_ips = set()
        for pkt in packets:
            if pkt.haslayer(IP):
                unique_src_ips.add(pkt[IP].src)
                unique_dst_ips.add(pkt[IP].dst)

        alerts.append(CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=base_time,
            category="network",
            event_name="traffic_summary",
            severity="low",
            confidence=1.0,
            description=(
                f"PCAP analysis complete: {total_packets} packets, "
                f"{len(unique_src_ips)} source IPs, {len(unique_dst_ips)} destination IPs, "
                f"{len(tcp_sessions)} TCP sessions, {len(dns_queries)} DNS queries"
            ),
            mitre_technique_ids=[],
            mitre_tactic="",
            risk_flags=[],
            extra_data={
                "total_packets": total_packets,
                "unique_src_ips": len(unique_src_ips),
                "unique_dst_ips": len(unique_dst_ips),
                "tcp_sessions": len(tcp_sessions),
                "dns_queries": len(dns_queries),
                "http_requests": len(http_requests),
                "suspicious_payloads": len(suspicious_payloads),
                "time_range": {
                    "start": pcap_start_time.isoformat() if pcap_start_time else None,
                    "end": pcap_end_time.isoformat() if pcap_end_time else None,
                },
                "top_talkers": dict(ip_connections.most_common(10)),
            },
        ))

    log.info(
        "pcap_analysis_complete",
        file=file_path,
        total_packets=total_packets,
        alerts_generated=len(alerts),
    )

    return alerts
