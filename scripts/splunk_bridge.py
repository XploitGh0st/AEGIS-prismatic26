"""
Splunk → AEGIS Bridge

Polls Splunk REST API for new Cowrie events and forwards them to AEGIS ingest API.
Runs as a long-lived process alongside the AEGIS backend.

Usage:
    python scripts/splunk_bridge.py

Environment variables:
    SPLUNK_HOST       - Splunk server (e.g., https://10.0.2.100:8089)
    SPLUNK_TOKEN      - Splunk Bearer token (or use SPLUNK_USER + SPLUNK_PASS)
    SPLUNK_USER       - Splunk username (default: admin)
    SPLUNK_PASS       - Splunk password
    AEGIS_API_URL     - AEGIS backend URL (default: http://localhost:8000)
    POLL_INTERVAL     - Seconds between polls (default: 30)
    SPLUNK_INDEX      - Index to query (default: cowrie)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib3
from datetime import datetime, timezone

import httpx

# Suppress InsecureRequestWarning for self-signed Splunk certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ────────────────────────────────────────
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS", "")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "cowrie")
AEGIS_API_URL = os.getenv("AEGIS_API_URL", "http://localhost:8000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))

# High-water mark file for deduplication
HWM_FILE = os.getenv("HWM_FILE", "/tmp/splunk_bridge_hwm.txt")

# Filter: only forward these Cowrie event types
INTERESTING_EVENTS = {
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
    "cowrie.direct-tcpip.request",
    "cowrie.client.version",
}


def get_splunk_auth_headers() -> dict:
    """Build auth headers for Splunk REST API."""
    if SPLUNK_TOKEN:
        return {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
    return {}


def get_splunk_auth() -> tuple[str, str] | None:
    """Return (user, pass) tuple for basic auth."""
    if SPLUNK_TOKEN:
        return None
    return (SPLUNK_USER, SPLUNK_PASS)


def read_high_water_mark() -> str:
    """Read the last-processed timestamp."""
    try:
        with open(HWM_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def write_high_water_mark(timestamp: str) -> None:
    """Write the high-water mark timestamp."""
    with open(HWM_FILE, "w") as f:
        f.write(timestamp)


def make_external_alert_id(event: dict) -> str:
    """Generate a dedup key from a Cowrie event."""
    key = f"{event.get('session', '')}_{event.get('eventid', '')}_{event.get('timestamp', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def poll_splunk(client: httpx.Client, earliest: str) -> list[dict]:
    """
    Run a Splunk search and return results.

    Uses the oneshot search endpoint for simplicity.
    """
    search_query = (
        f'search index={SPLUNK_INDEX} sourcetype="cowrie:json" '
        f'earliest="{earliest}" latest=now '
        f'| table _raw'
    )

    try:
        response = client.post(
            f"{SPLUNK_HOST}/services/search/jobs/export",
            data={
                "search": search_query,
                "output_mode": "json",
                "count": 500,
            },
            headers=get_splunk_auth_headers(),
            auth=get_splunk_auth(),
            verify=False,
            timeout=60,
        )
        response.raise_for_status()

        events = []
        for line in response.text.strip().split("\n"):
            if not line.strip():
                continue
            try:
                wrapper = json.loads(line)
                if "result" in wrapper:
                    raw = wrapper["result"].get("_raw", "")
                    if raw:
                        event = json.loads(raw)
                        events.append(event)
            except (json.JSONDecodeError, KeyError):
                continue

        return events

    except Exception as e:
        print(f"[ERROR] Splunk poll failed: {e}")
        return []


def forward_to_aegis(client: httpx.Client, events: list[dict]) -> int:
    """Forward Cowrie events to AEGIS ingest API."""
    alerts = []
    for event in events:
        eventid = event.get("eventid", "")
        if eventid not in INTERESTING_EVENTS:
            continue

        alert = {
            "source_family": "siem",
            "source_type": "cowrie_splunk",
            "external_alert_id": make_external_alert_id(event),
            "event_time": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "payload": event,
        }
        alerts.append(alert)

    if not alerts:
        return 0

    try:
        response = client.post(
            f"{AEGIS_API_URL}/api/v1/alerts/bulk?sync_processing=true",
            json={"alerts": alerts},
            timeout=120,
        )
        response.raise_for_status()
        result = response.json()
        return result.get("accepted", 0)
    except Exception as e:
        print(f"[ERROR] AEGIS forward failed: {e}")
        return 0


def main():
    """Main bridge loop."""
    print(f"[INFO] Splunk Bridge starting")
    print(f"[INFO] Splunk: {SPLUNK_HOST}")
    print(f"[INFO] AEGIS:  {AEGIS_API_URL}")
    print(f"[INFO] Index:  {SPLUNK_INDEX}")
    print(f"[INFO] Poll interval: {POLL_INTERVAL}s")

    with httpx.Client() as client:
        while True:
            try:
                # Determine search window
                hwm = read_high_water_mark()
                if not hwm:
                    earliest = f"-{POLL_INTERVAL * 2}s"
                else:
                    earliest = hwm

                # Poll Splunk
                events = poll_splunk(client, earliest)
                if events:
                    print(f"[INFO] Polled {len(events)} events from Splunk")

                    # Forward to AEGIS
                    accepted = forward_to_aegis(client, events)
                    print(f"[INFO] Forwarded {accepted} alerts to AEGIS")

                    # Update high-water mark
                    latest_ts = max(
                        e.get("timestamp", "") for e in events
                    )
                    if latest_ts:
                        write_high_water_mark(latest_ts)
                else:
                    print(f"[DEBUG] No new events")

            except KeyboardInterrupt:
                print("[INFO] Bridge stopping")
                break
            except Exception as e:
                print(f"[ERROR] Bridge error: {e}")

            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
