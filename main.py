#!/usr/bin/env python3
"""
ARP Spoofing Defense System

Detects ARP spoofing attacks and responds with passive defense (alerts, logging,
ARP restoration) and optionally active defense (honeytoken injection).

Usage:
    python main.py                     # Basic detection and defense
    python main.py --deception         # Enable honeytoken injection
    python main.py --beacon my.domain  # Custom beacon domain for tracking

Requires root/administrator privileges for packet capture.
"""

import argparse
import sys
import logging

from detector import ArpSpoofDetector, GatewayResolutionError
from responders import (
    LogResponder,
    AlertResponder,
    ArpRestorationResponder,
    CompositeResponder
)
from deception import DeceptionResponder
from defense_system import DefenseSystem


def setup_logging(verbose: bool = False):
    """Configure application logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Defense System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                     Basic detection and defense
  python main.py --deception         Enable honeytoken injection
  python main.py --beacon my.domain  Custom beacon domain for tracking
  python main.py --gateway 192.168.1.1  Manual gateway IP (skips auto-detection)
        """
    )
    parser.add_argument(
        "--deception",
        action="store_true",
        help="Enable active defense with honeytoken injection"
    )
    parser.add_argument(
        "--beacon",
        type=str,
        default="canary.yourdomain.com",
        help="Domain for tracking beacon URLs (default: canary.yourdomain.com)"
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface to monitor"
    )
    parser.add_argument(
        "--gateway",
        type=str,
        default=None,
        help="Gateway IP to monitor (auto-detected if not specified)"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default="attack_log.txt",
        help="File to log detected attacks (default: attack_log.txt)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--no-restore",
        action="store_true",
        help="Disable ARP table restoration (alert and log only)"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)

    print("\n" + "=" * 50)
    print("  ARP Spoofing Defense System")
    print("=" * 50 + "\n")

    # Initialize detector with proper error handling
    try:
        detector = ArpSpoofDetector(gateway_ip=args.gateway)
    except GatewayResolutionError as e:
        print(f"[Error] {e}")
        print("\nTroubleshooting:")
        print("  - Check your network connection")
        print("  - Try specifying --gateway manually")
        print("  - Make sure you're not on a VPN that hides the gateway")
        sys.exit(1)
    except Exception as e:
        print(f"[Error] Unexpected error initializing detector: {e}")
        sys.exit(1)

    # Build responder chain
    responder_chain = [
        AlertResponder(),
        LogResponder(args.log_file),
    ]

    if not args.no_restore:
        responder_chain.append(ArpRestorationResponder(interface=args.interface))

    if args.deception:
        print("[Config] Active defense ENABLED - honeytokens will be injected")
        try:
            deception_responder = DeceptionResponder(
                beacon_domain=args.beacon,
                injection_count=10,
                interface=args.interface
            )
            responder_chain.append(deception_responder)
        except ValueError as e:
            print(f"[Error] Invalid deception config: {e}")
            sys.exit(1)

    responder = CompositeResponder(responder_chain)

    # Initialize and start defense system
    system = DefenseSystem(
        detector=detector,
        responder=responder,
        listen_ip=None,
        continuous=True
    )

    print()  # Visual separation before sniffing starts

    try:
        system.start()
    except PermissionError:
        print("\n[Error] Permission denied. Run as Administrator (Windows) or root (Linux)")
        print("  Windows: Right-click cmd -> 'Run as Administrator'")
        print("  Linux:   sudo python main.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[System] Interrupted")
    except Exception as e:
        print(f"\n[Error] {e}")
        logging.exception("Unhandled exception")
        sys.exit(1)


if __name__ == "__main__":
    main()
