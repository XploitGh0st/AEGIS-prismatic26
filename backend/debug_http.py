"""Debug: raw HTTP response from scenario endpoint."""
import httpx

r = httpx.post(
    "http://localhost:8000/api/v1/scenarios/run/cve_exploitation_chain",
    params={"auto_summarize": False, "generation_type": "deterministic"},
    timeout=120.0,
)
print(f"HTTP {r.status_code}")
print(r.text[:3000])
