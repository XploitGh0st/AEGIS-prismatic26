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
- JNDI injection detection (Log4Shell / CVE-2021-44228)
- Malicious LDAP/RMI server callback detection
- Java deserialization attack detection
- C2 beaconing detection
- CVE signature matching engine
"""

from __future__ import annotations

import hashlib
import os
import re
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
    # Java / JNDI / Exploit-specific patterns
    b"${jndi:", b"${lower:", b"${upper:",
    b"javax.naming", b"java.lang.Runtime",
    b"getRuntime", b"ProcessBuilder",
    b"java.io.ObjectInputStream",
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

# ── Java serialization magic bytes ──────────────────────
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"

# ── Known malicious Java gadget classes ─────────────────
JAVA_GADGET_CLASSES = [
    b"org.apache.naming.ResourceRef",
    b"org.apache.naming.AbstractRef",
    b"javax.naming.Reference",
    b"javax.naming.StringRefAddr",
    b"com.sun.jndi.rmi",
    b"java.lang.Runtime",
    b"java.lang.ProcessBuilder",
    b"org.apache.xalan",
    b"org.apache.commons.collections",
    b"sun.reflect.annotation",
    b"com.sun.rowset.JdbcRowSetImpl",
    b"org.springframework.beans.factory",
    b"bsh.Interpreter",
]

# ── JNDI injection patterns (including obfuscated) ─────
JNDI_PATTERNS = [
    # Standard
    rb'\$\{jndi:',
    # Case-obfuscated variants
    rb'\$\{\$\{[^}]*\}ndi:',
    rb'\$\{j\$\{[^}]*\}di:',
    rb'\$\{jn\$\{[^}]*\}i:',
    rb'\$\{jnd\$\{[^}]*\}:',
    # Lookup obfuscation
    rb'\$\{\$\{(?:lower|upper|env|sys|java):',
    # Unicode / encoding tricks
    rb'\$\{j(?:\$\{[^}]+\})*n(?:\$\{[^}]+\})*d(?:\$\{[^}]+\})*i(?:\$\{[^}]+\})*:',
]

# ── CVE signature definitions ──────────────────────────
CVE_SIGNATURES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-44228",
        "name": "Apache Log4Shell RCE",
        "description": "Log4j2 JNDI injection leading to remote code execution",
        "payload_patterns": [rb'\$\{jndi:', rb'\$\{j\$\{', rb'jndi:ldap://', rb'jndi:rmi://'],
        "response_indicators": [b"log4j", b"Log4j2", b"com.sun.jndi"],
        "associated_ports": {1389, 1099, 8888, 9999},
        "mitre_techniques": ["T1190", "T1203", "T1059"],
        "severity": "critical",
        "confidence": 0.95,
    },
    {
        "cve_id": "CVE-2021-45046",
        "name": "Log4Shell Bypass (Thread Context)",
        "description": "Log4j2 incomplete fix bypass via Thread Context patterns",
        "payload_patterns": [rb'\$\{ctx:', rb'\$\{jndi:'],
        "response_indicators": [b"log4j", b"Log4j2"],
        "associated_ports": {1389, 1099},
        "mitre_techniques": ["T1190", "T1203"],
        "severity": "critical",
        "confidence": 0.90,
    },
    {
        "cve_id": "CVE-2017-5638",
        "name": "Apache Struts2 RCE",
        "description": "OGNL injection via Content-Type header",
        "payload_patterns": [rb'%\{.*\}', rb'ognl\.OgnlContext'],
        "response_indicators": [b"struts", b"ognl"],
        "associated_ports": set(),
        "mitre_techniques": ["T1190"],
        "severity": "critical",
        "confidence": 0.85,
    },
]

# ── Non-standard ports for naming services ──────────────
NAMING_SERVICE_PORTS = {389, 636, 1389, 1099, 8888, 9999, 10389}


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
    8. Detect JNDI injection attacks (Log4Shell)
    9. Detect malicious LDAP/RMI callbacks
    10. Detect Java deserialization attacks
    11. Detect C2 beaconing patterns
    12. Match CVE signatures
    13. Generate alerts for each finding
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

    # New: exploit-specific data collection
    jndi_injections: list[dict] = []
    ldap_rmi_callbacks: list[dict] = []
    java_deser_attacks: list[dict] = []
    http_beacons: dict[str, list[dict]] = defaultdict(list)  # dst_key → list of requests
    cve_matches: list[dict] = []

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

            # HTTP traffic (expanded port list)
            if tcp.dport in (80, 443, 8080, 8443, 8888) or tcp.sport in (80, 443, 8080, 8443, 8888):
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    if payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"PUT "):
                        try:
                            lines = payload.split(b"\r\n")
                            first_line = lines[0].decode("utf-8", errors="replace")

                            # Extract headers for deeper inspection
                            headers = {}
                            for line in lines[1:]:
                                if b":" in line:
                                    k, _, v = line.partition(b":")
                                    headers[k.decode("utf-8", errors="replace").strip().lower()] = \
                                        v.decode("utf-8", errors="replace").strip()

                            req_info = {
                                "time": pkt_time,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": tcp.sport,
                                "dst_port": tcp.dport,
                                "request": first_line,
                                "headers": headers,
                                "size": len(payload),
                                "raw_payload": payload,
                            }
                            http_requests.append(req_info)

                            # Track beaconing — group by destination
                            beacon_key = f"{dst_ip}:{tcp.dport}"
                            http_beacons[beacon_key].append(req_info)

                        except Exception:
                            pass

            # ── JNDI injection detection ─────────────────
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                payload_lower = payload.lower()

                for pattern in JNDI_PATTERNS:
                    match = re.search(pattern, payload, re.IGNORECASE)
                    if match:
                        # Extract the full JNDI string
                        start = match.start()
                        # Find the matching closing brace
                        jndi_str = _extract_jndi_string(payload[start:])

                        # Determine which field contains the injection
                        injection_field = _identify_injection_field(payload, start)

                        # Extract callback URL
                        callback_url = _extract_callback_url(jndi_str)
                        callback_protocol = _extract_callback_protocol(jndi_str)

                        jndi_injections.append({
                            "time": pkt_time,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "jndi_string": jndi_str,
                            "callback_url": callback_url,
                            "callback_protocol": callback_protocol,
                            "injection_field": injection_field,
                            "payload_preview": payload[:500].decode("utf-8", errors="replace"),
                        })
                        break  # One detection per packet

                # ── LDAP/RMI callback detection ──────────
                if tcp.dport in NAMING_SERVICE_PORTS or tcp.sport in NAMING_SERVICE_PORTS:
                    # Check if this is a naming service response (not just SYN/ACK)
                    if len(payload) > 10:
                        is_response = tcp.sport in NAMING_SERVICE_PORTS
                        ldap_rmi_callbacks.append({
                            "time": pkt_time,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "direction": "response" if is_response else "request",
                            "service_port": tcp.sport if is_response else tcp.dport,
                            "payload_size": len(payload),
                            "has_java_serial": JAVA_SERIAL_MAGIC in payload,
                            "payload_preview": payload[:200].decode("utf-8", errors="replace"),
                        })

                # ── Java deserialization detection ────────
                if JAVA_SERIAL_MAGIC in payload:
                    # Extract class names from the serialized stream
                    classes = _extract_java_classes(payload)
                    gadget_hits = [c for c in classes if any(g in c.encode() for g in JAVA_GADGET_CLASSES)]

                    java_deser_attacks.append({
                        "time": pkt_time,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": tcp.sport,
                        "dst_port": tcp.dport,
                        "classes_found": classes[:20],
                        "gadget_chains": gadget_hits,
                        "payload_size": len(payload),
                        "serial_offset": payload.find(JAVA_SERIAL_MAGIC),
                    })

            # ── CVE signature matching ───────────────────
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                for sig in CVE_SIGNATURES:
                    for pat in sig["payload_patterns"]:
                        if re.search(pat, payload, re.IGNORECASE):
                            # Check for associated ports
                            port_match = (
                                not sig["associated_ports"]
                                or tcp.dport in sig["associated_ports"]
                                or tcp.sport in sig["associated_ports"]
                            )
                            if port_match:
                                cve_matches.append({
                                    "time": pkt_time,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": tcp.sport,
                                    "dst_port": tcp.dport,
                                    "cve_id": sig["cve_id"],
                                    "cve_name": sig["name"],
                                    "cve_description": sig["description"],
                                    "mitre_techniques": sig["mitre_techniques"],
                                    "severity": sig["severity"],
                                    "confidence": sig["confidence"],
                                    "matched_pattern": pat.pattern if hasattr(pat, 'pattern') else str(pat),
                                    "payload_preview": payload[:300].decode("utf-8", errors="replace"),
                                })
                                break  # One CVE match per packet per signature
                    # Only match the first CVE signature per packet
                    if cve_matches and cve_matches[-1].get("time") == pkt_time:
                        break

            # Payload inspection (original generic patterns)
            if pkt.haslayer(Raw) and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                payload = pkt[Raw].load
                for pattern in SUSPICIOUS_PAYLOAD_PATTERNS:
                    if pattern in payload:
                        # Skip if already caught by JNDI detector
                        if pattern in (b"${jndi:", b"${lower:", b"${upper:"):
                            break
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

    # ── NEW DETECTORS ────────────────────────────────────

    # 7. JNDI Injection Detection (Log4Shell and variants)
    seen_jndi_srcs = set()
    for inj in jndi_injections:
        # Deduplicate by source IP (multiple packets may carry the same injection)
        dedup_key = f"{inj['src_ip']}->{inj['dst_ip']}:{inj['dst_port']}"
        if dedup_key in seen_jndi_srcs:
            continue
        seen_jndi_srcs.add(dedup_key)

        alerts.append(CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=inj["time"],
            category="execution",
            event_name="jndi_injection",
            severity="critical",
            confidence=0.95,
            source_ip=inj["src_ip"],
            destination_ip=inj["dst_ip"],
            source_port=inj["src_port"],
            destination_port=inj["dst_port"],
            description=(
                f"JNDI injection attack detected targeting {inj['dst_ip']}:{inj['dst_port']}. "
                f"Callback via {inj['callback_protocol'].upper()} to {inj['callback_url']}. "
                f"Injection in {inj['injection_field']}."
            ),
            mitre_technique_ids=["T1190", "T1659"],
            mitre_tactic="initial_access",
            risk_flags=["jndi_injection", "log4shell", "cve_exploit", "rce"],
            raw_command=inj["jndi_string"][:500],
            extra_data={
                "jndi_string": inj["jndi_string"][:500],
                "callback_url": inj["callback_url"],
                "callback_protocol": inj["callback_protocol"],
                "injection_field": inj["injection_field"],
                "cve_id": "CVE-2021-44228",
            },
        ))

    # 8. Malicious LDAP/RMI Server Detection
    # Group callbacks by flow direction
    callback_flows: dict[str, list] = defaultdict(list)
    for cb in ldap_rmi_callbacks:
        flow_key = f"{cb['src_ip']}:{cb['service_port']}->{cb['dst_ip']}"
        callback_flows[flow_key].append(cb)

    for flow_key, callbacks in callback_flows.items():
        if not callbacks:
            continue

        first = callbacks[0]
        responses = [c for c in callbacks if c["direction"] == "response"]
        has_java = any(c["has_java_serial"] for c in callbacks)
        total_bytes = sum(c["payload_size"] for c in callbacks)

        severity = "critical" if has_java else "high"
        conf = 0.90 if has_java else 0.80

        alerts.append(CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=first["time"],
            category="network",
            event_name="malicious_naming_service",
            severity=severity,
            confidence=conf,
            source_ip=first["src_ip"],
            destination_ip=first["dst_ip"],
            source_port=first["src_port"],
            destination_port=first["dst_port"],
            description=(
                f"Malicious naming service detected on port {first['service_port']}. "
                f"{len(callbacks)} packets, {len(responses)} responses, "
                f"{total_bytes} bytes transferred"
                f"{'. Contains Java serialized objects!' if has_java else '.'}"
            ),
            mitre_technique_ids=["T1071"],
            mitre_tactic="command_and_control",
            risk_flags=["malicious_ldap", "naming_service_attack"]
                       + (["java_serialized_payload"] if has_java else []),
            extra_data={
                "service_port": first["service_port"],
                "packet_count": len(callbacks),
                "response_count": len(responses),
                "total_bytes": total_bytes,
                "has_java_serialized": has_java,
            },
        ))

    # 9. Java Deserialization Attack Detection
    seen_deser = set()
    for deser in java_deser_attacks:
        dedup_key = f"{deser['src_ip']}->{deser['dst_ip']}:{deser['dst_port']}"
        if dedup_key in seen_deser:
            continue
        seen_deser.add(dedup_key)

        is_gadget = len(deser["gadget_chains"]) > 0
        severity = "critical" if is_gadget else "high"
        conf = 0.95 if is_gadget else 0.75

        alerts.append(CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=deser["time"],
            category="execution",
            event_name="java_deserialization",
            severity=severity,
            confidence=conf,
            source_ip=deser["src_ip"],
            destination_ip=deser["dst_ip"],
            source_port=deser["src_port"],
            destination_port=deser["dst_port"],
            description=(
                f"Java deserialization attack: serialized object delivered from "
                f"{deser['src_ip']} to {deser['dst_ip']}. "
                f"{len(deser['classes_found'])} classes found"
                f"{', KNOWN GADGET CHAINS: ' + ', '.join(deser['gadget_chains'][:5]) if is_gadget else '.'}"
            ),
            mitre_technique_ids=["T1203", "T1059"],
            mitre_tactic="execution",
            risk_flags=["java_deserialization", "rce"]
                       + (["known_gadget_chain"] if is_gadget else []),
            extra_data={
                "classes_found": deser["classes_found"][:20],
                "gadget_chains": deser["gadget_chains"],
                "payload_size": deser["payload_size"],
                "serial_offset": deser["serial_offset"],
            },
        ))

    # 10. C2 Beaconing Detection
    for dst_key, reqs in http_beacons.items():
        if len(reqs) < 3:
            continue

        # Check for beaconing indicators
        times = sorted([r["time"] for r in reqs])
        intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times) - 1)]

        # Check for rotating cookies (different cookie per request)
        cookies = set()
        for r in reqs:
            cookie = r["headers"].get("cookie", "")
            if cookie:
                cookies.add(cookie)

        # Check for fixed user-agent
        user_agents = set()
        for r in reqs:
            ua = r["headers"].get("user-agent", "")
            if ua:
                user_agents.add(ua)

        # Beaconing heuristics
        has_rotating_cookies = len(cookies) >= 2 and len(cookies) == len(reqs)
        has_uniform_ua = len(user_agents) == 1
        has_regular_intervals = False
        if intervals and len(intervals) >= 2:
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval > 0:
                variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                has_regular_intervals = (variance / max(avg_interval ** 2, 1)) < 0.25  # Low variance

        beacon_score = sum([has_rotating_cookies, has_uniform_ua, has_regular_intervals])

        if beacon_score >= 2:
            first = reqs[0]
            paths = [r["request"].split(" ")[1] if " " in r["request"] else "?" for r in reqs]

            alerts.append(CanonicalAlert(
                source_family="ids",
                source_type="pcap_analysis",
                event_time=first["time"],
                category="network",
                event_name="c2_beaconing",
                severity="high",
                confidence=min(0.95, 0.6 + beacon_score * 0.1),
                source_ip=first["src_ip"],
                destination_ip=first["dst_ip"],
                destination_port=first["dst_port"],
                description=(
                    f"C2 beaconing detected: {len(reqs)} requests to {dst_key}. "
                    f"Indicators: "
                    + ", ".join(filter(None, [
                        "rotating cookies" if has_rotating_cookies else None,
                        "uniform User-Agent" if has_uniform_ua else None,
                        f"regular intervals (~{sum(intervals)/len(intervals):.0f}s)" if has_regular_intervals else None,
                    ]))
                ),
                mitre_technique_ids=["T1071", "T1573"],
                mitre_tactic="command_and_control",
                risk_flags=["c2_beacon", "periodic_callback"]
                           + (["rotating_session"] if has_rotating_cookies else []),
                extra_data={
                    "request_count": len(reqs),
                    "paths": paths[:10],
                    "intervals": [round(i, 1) for i in intervals[:10]],
                    "rotating_cookies": has_rotating_cookies,
                    "uniform_user_agent": has_uniform_ua,
                    "regular_intervals": has_regular_intervals,
                    "user_agent": list(user_agents)[0] if user_agents else None,
                },
            ))

    # 11. CVE Signature Match Alerts
    seen_cves: set[str] = set()
    for match in cve_matches:
        # Deduplicate by CVE + source/dest pair
        dedup_key = f"{match['cve_id']}:{match['src_ip']}->{match['dst_ip']}"
        if dedup_key in seen_cves:
            continue
        seen_cves.add(dedup_key)

        alerts.append(CanonicalAlert(
            source_family="ids",
            source_type="pcap_analysis",
            event_time=match["time"],
            category="execution",
            event_name="cve_exploit",
            severity=match["severity"],
            confidence=match["confidence"],
            source_ip=match["src_ip"],
            destination_ip=match["dst_ip"],
            source_port=match["src_port"],
            destination_port=match["dst_port"],
            description=(
                f"CVE exploit detected: {match['cve_id']} ({match['cve_name']}). "
                f"{match['cve_description']}"
            ),
            mitre_technique_ids=match["mitre_techniques"],
            mitre_tactic="initial_access",
            risk_flags=["cve_exploit", match["cve_id"].lower().replace("-", "_")],
            extra_data={
                "cve_id": match["cve_id"],
                "cve_name": match["cve_name"],
                "cve_description": match["cve_description"],
            },
        ))

    # 12. Generate a traffic summary alert
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
                + (f", {len(jndi_injections)} JNDI injections" if jndi_injections else "")
                + (f", {len(java_deser_attacks)} Java deser attacks" if java_deser_attacks else "")
                + (f", {len(cve_matches)} CVE signature hits" if cve_matches else "")
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
                "jndi_injections": len(jndi_injections),
                "ldap_rmi_callbacks": len(ldap_rmi_callbacks),
                "java_deser_attacks": len(java_deser_attacks),
                "cve_matches": len(cve_matches),
                "c2_beacons": sum(1 for k, v in http_beacons.items() if len(v) >= 3),
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
        jndi_injections=len(jndi_injections),
        java_deser=len(java_deser_attacks),
        cve_matches=len(cve_matches),
    )

    return alerts


# ── Helper Functions ─────────────────────────────────────

def _extract_jndi_string(payload_fragment: bytes) -> str:
    """Extract the full ${jndi:...} string from a payload fragment."""
    try:
        text = payload_fragment.decode("utf-8", errors="replace")
    except Exception:
        return "(binary)"

    depth = 0
    result = []
    for ch in text:
        if ch == "$" and not result:
            result.append(ch)
        elif result:
            result.append(ch)
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth <= 0:
                    break

    extracted = "".join(result) if result else text[:100]
    return extracted[:500]


def _extract_callback_url(jndi_string: str) -> str:
    """Extract the callback URL from a JNDI string."""
    # Try to find ldap://, rmi://, dns:// patterns
    for proto in ["ldap://", "rmi://", "ldaps://", "dns://", "iiop://"]:
        idx = jndi_string.lower().find(proto)
        if idx >= 0:
            url = jndi_string[idx:]
            # Trim at closing brace or whitespace
            for end_ch in ["}", " ", "\r", "\n", "\t", ","]:
                end_idx = url.find(end_ch)
                if end_idx > 0:
                    url = url[:end_idx]
            return url
    return "(embedded)"


def _extract_callback_protocol(jndi_string: str) -> str:
    """Identify the callback protocol (ldap, rmi, dns, etc.)."""
    lower = jndi_string.lower()
    for proto in ["ldap", "ldaps", "rmi", "dns", "iiop", "http", "https"]:
        if f"{proto}://" in lower:
            return proto
    return "unknown"


def _identify_injection_field(payload: bytes, jndi_offset: int) -> str:
    """Identify which HTTP field contains the JNDI injection."""
    try:
        text = payload[:jndi_offset].decode("utf-8", errors="replace")
    except Exception:
        return "unknown"

    # Look backwards from the injection point for header names
    lower = text.lower()
    header_markers = [
        ("user-agent:", "User-Agent header"),
        ("referer:", "Referer header"),
        ("x-forwarded-for:", "X-Forwarded-For header"),
        ("x-api-version:", "X-API-Version header"),
        ("authorization:", "Authorization header"),
        ("cookie:", "Cookie header"),
        ("content-type:", "Content-Type header"),
        ("accept:", "Accept header"),
        ("x-", "custom header"),
    ]

    for marker, label in header_markers:
        if marker in lower:
            return label

    # Check if it's in the URL path
    if text.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
        return "URL path/query"

    # Check if it's in the body
    if "\r\n\r\n" in text:
        return "request body"

    return "HTTP header"


def _extract_java_classes(payload: bytes) -> list[str]:
    """Extract Java class names from a serialized object stream."""
    classes = []
    try:
        # Find class name patterns in the binary stream
        # Java serialized class names are typically in the format:
        # package.name.ClassName
        pattern = rb'[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*){2,}'
        matches = re.findall(pattern, payload)
        seen = set()
        for m in matches:
            try:
                class_name = m.decode("utf-8")
                if class_name not in seen and len(class_name) > 5:
                    seen.add(class_name)
                    classes.append(class_name)
            except Exception:
                continue
    except Exception:
        pass
    return classes
