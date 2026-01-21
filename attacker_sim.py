"""
Attacker Simulation - Demonstrates how attackers fall for honeytokens

This script simulates what an attacker would do after capturing honeytokens:
1. Parse captured credentials
2. Try to use them (hitting the canary server)
3. Get caught

Run this on Kali (or any machine) to demonstrate the trap working.

Usage:
    python attacker_sim.py --token-file deception_log.txt
    python attacker_sim.py --beacon-url http://192.168.0.103/webhook/abc123
"""

import argparse
import re
import sys
import urllib.request
import urllib.error


def parse_tokens_from_log(log_file):
    tokens = []

    try:
        with open(log_file, "r") as f:
            for line in f:
                match = re.search(r"Beacon: (http://[^\s]+)", line)
                if match:
                    tokens.append({
                        "beacon_url": match.group(1),
                        "line": line.strip()
                    })
    except FileNotFoundError:
        print(f"[Error] File not found: {log_file}")
        return []

    return tokens


def try_beacon_url(url):
    print(f"\n[Attacker] Trying to verify captured credentials...")
    print(f"[Attacker] Hitting: {url}")

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "curl/7.68.0"}
        )
        response = urllib.request.urlopen(req, timeout=5)

        print(f"[Attacker] Response: {response.status}")
        print(f"[Attacker] Looks like the credentials might be valid!")
        print()
        print("[REALITY] You just got CAUGHT. The defender now has your IP.")
        return True

    except urllib.error.URLError as e:
        print(f"[Attacker] Connection failed: {e.reason}")
        print("[Info] Make sure canary_server.py is running on the target")
        return False
    except Exception as e:
        print(f"[Attacker] Error: {e}")
        return False


def simulate_credential_theft():
    print("\n" + "=" * 60)
    print("  ATTACKER PERSPECTIVE - What they see after MITM")
    print("=" * 60)

    fake_captured_data = """
[CAPTURED TRAFFIC]

--- Packet 1 ---
# Production API Configuration
API_KEY=sk_live_a1b2c3d4_9f8e7d6c5b4a3f2e1d0c9b8a7
API_SECRET=ABCDEFGHIJKLMNOP0123456789QRSTUV
WEBHOOK_URL=http://canary.target.com/webhook/a1b2c3d4

--- Packet 2 ---
Host: internal-db.corp.local
Username: svc_admin_x7y8z9
Password: Pr0d#kj3nf8wnc93md
Verify at: http://canary.target.com/verify/x7y8z9

--- Packet 3 ---
{
  "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
  "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "s3_bucket": "backup-q1w2e3-prod",
  "health_check": "http://canary.target.com/health/q1w2e3"
}
    """

    print(fake_captured_data)

    print("\n[Attacker] Jackpot! Look at all these credentials!")
    print("[Attacker] Let me try the AWS keys first...")
    print()
    print("=" * 60)
    print("  THE TRAP")
    print("=" * 60)
    print()
    print("If the attacker tries to:")
    print("  - Use the API key → webhook URL gets hit → CAUGHT")
    print("  - Verify credentials → verify URL gets hit → CAUGHT")
    print("  - Check AWS health → health URL gets hit → CAUGHT")
    print()
    print("Every honeytoken has a tracking beacon embedded.")
    print("The attacker cannot know which credentials are real vs fake.")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Attacker Simulation - Demonstrate honeytoken trap",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--token-file",
        type=str,
        default=None,
        help="Path to deception_log.txt to parse real honeytokens"
    )
    parser.add_argument(
        "--beacon-url",
        type=str,
        default=None,
        help="Specific beacon URL to test (simulates attacker using captured token)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Show demonstration of what attacker sees"
    )

    args = parser.parse_args()

    if args.demo or (not args.token_file and not args.beacon_url):
        simulate_credential_theft()

    if args.beacon_url:
        print("\n" + "=" * 60)
        print("  SIMULATING ATTACKER USING STOLEN CREDENTIAL")
        print("=" * 60)
        try_beacon_url(args.beacon_url)

    if args.token_file:
        print("\n" + "=" * 60)
        print("  PARSING CAPTURED HONEYTOKENS")
        print("=" * 60)

        tokens = parse_tokens_from_log(args.token_file)

        if not tokens:
            print("[Info] No tokens found in file")
            return

        print(f"\n[Attacker] Found {len(tokens)} potential credentials!\n")

        for i, token in enumerate(tokens[:3]):
            print(f"  [{i + 1}] {token['beacon_url']}")

        print("\n[Attacker] Trying to verify the first one...")

        if tokens:
            try_beacon_url(tokens[0]["beacon_url"])


if __name__ == "__main__":
    main()
