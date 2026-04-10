"""
AEGIS Tests — Scoring service tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.services.scoring_service import compute_severity_score, severity_label


def _make_incident(**kwargs):
    """Create a mock incident with defaults."""
    mock = MagicMock()
    mock.classification = kwargs.get("classification", "reconnaissance")
    mock.mitre_techniques = kwargs.get("mitre_techniques", [])
    mock.mitre_tactics = kwargs.get("mitre_tactics", [])
    mock.primary_user = kwargs.get("primary_user", None)
    mock.source_families = kwargs.get("source_families", ["siem"])
    mock.alert_count = kwargs.get("alert_count", 1)
    mock.scoring_breakdown = {}
    return mock


def test_base_score_recon():
    """Reconnaissance gets base 15."""
    inc = _make_incident(classification="reconnaissance")
    score = compute_severity_score(inc)
    assert score == 15


def test_base_score_account_compromise():
    """Account compromise gets base 35."""
    inc = _make_incident(classification="account_compromise")
    score = compute_severity_score(inc)
    assert score == 35


def test_privileged_user_bonus():
    """Root user should get +10 bonus."""
    inc = _make_incident(
        classification="account_compromise",
        primary_user="root",
    )
    score = compute_severity_score(inc)
    assert score == 45  # 35 base + 10 privileged


def test_multi_source_bonus():
    """Multi-source incidents get bonus."""
    inc = _make_incident(
        classification="brute_force_attempt",
        source_families=["siem", "ids"],
    )
    score = compute_severity_score(inc)
    assert score == 28  # 20 base + 8 multi-source


def test_execution_bonus():
    """Execution techniques get +10, T1078 also adds +5 persistence."""
    inc = _make_incident(
        classification="account_compromise",
        mitre_techniques=["T1059", "T1078"],
    )
    score = compute_severity_score(inc)
    assert score == 50  # 35 base + 10 execution + 5 persistence (T1078)


def test_attack_chain_bonus():
    """Full attack chain gets +10."""
    inc = _make_incident(
        classification="account_compromise",
        mitre_techniques=["T1110", "T1078", "T1059"],
        primary_user="root",
    )
    score = compute_severity_score(inc)
    # 35 base + 10 privileged + 10 execution + 10 attack chain + 5 persistence (T1078) = 70
    assert score == 70


def test_full_cowrie_attack():
    """Full Cowrie attack chain should score critical."""
    inc = _make_incident(
        classification="account_compromise",
        mitre_techniques=["T1046", "T1110", "T1078", "T1059", "T1105"],
        primary_user="root",
        source_families=["siem"],
        alert_count=20,
    )
    score = compute_severity_score(inc)
    # 35 base + 10 privileged + 10 execution + 10 attack chain + 8 volume = 73
    assert score >= 70
    assert severity_label(score) in ("high", "critical")


def test_severity_labels():
    """Test severity label thresholds."""
    assert severity_label(10) == "low"
    assert severity_label(24) == "low"
    assert severity_label(25) == "medium"
    assert severity_label(49) == "medium"
    assert severity_label(50) == "high"
    assert severity_label(74) == "high"
    assert severity_label(75) == "critical"
    assert severity_label(100) == "critical"


def test_score_clamped():
    """Score should be clamped to 100."""
    inc = _make_incident(
        classification="account_compromise",
        mitre_techniques=["T1046", "T1110", "T1078", "T1059", "T1105", "T1548", "T1041"],
        primary_user="root",
        source_families=["siem", "edr", "ids"],
        alert_count=50,
    )
    score = compute_severity_score(inc)
    assert score <= 100
