"""Test the AEGIS pipeline: run a scenario and verify incident creation + summary."""
import httpx
import json
import sys

BASE = "http://localhost:8000/api/v1"

def test_scenario(name, gen_type="deterministic"):
    print(f"\n{'='*60}")
    print(f"  Running scenario: {name}")
    print(f"{'='*60}")

    r = httpx.post(
        f"{BASE}/scenarios/run/{name}",
        params={"auto_summarize": True, "generation_type": gen_type},
        timeout=120.0,
    )

    if r.status_code != 200:
        print(f"  ERROR: HTTP {r.status_code}")
        print(f"  {r.text[:500]}")
        return False

    data = r.json()
    print(f"  Ingested:  {data.get('ingested')}/{data.get('total_alerts')} alerts")
    print(f"  Errors:    {data.get('errors')}")
    print(f"  Incidents: {data.get('incidents_created')} created")
    print(f"  Summaries: {data.get('incidents_summarized')} generated")
    print(f"  Expected:  {data.get('expected_incidents')} incidents")

    for i, inc in enumerate(data.get("incidents", [])):
        print(f"\n  --- Incident {i+1} ---")
        print(f"  Title: {inc['title']}")
        print(f"  Severity: {inc['severity']} (score: {inc['severity_score']})")
        print(f"  Classification: {inc['classification']}")
        print(f"  Alert Count: {inc['alert_count']}")
        print(f"  MITRE: {', '.join(inc.get('mitre_techniques', []))}")
        print(f"  Summary Type: {inc.get('summary_type')}")
        summary = inc.get("executive_summary", "N/A")
        print(f"  Executive Summary: {summary[:300]}")
        root_cause = inc.get("root_cause", "N/A")
        print(f"  Root Cause: {root_cause}")

    return True


if __name__ == "__main__":
    scenarios = sys.argv[1:] if len(sys.argv) > 1 else ["cve_exploitation_chain"]
    gen_type = "deterministic"

    for s in scenarios:
        test_scenario(s, gen_type)

    print("\n\nDone!")
