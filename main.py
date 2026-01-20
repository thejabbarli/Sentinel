import argparse

from detector import ArpSpoofDetector
from responders import (
    LogResponder,
    AlertResponder,
    ArpRestorationResponder,
    CompositeResponder
)
from deception import DeceptionResponder
from defense_system import DefenseSystem


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Defense System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                     Basic detection and defense
  python main.py --deception         Enable honeytoken injection
  python main.py --beacon my.domain  Custom beacon domain for tracking
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

    args = parser.parse_args()

    detector = ArpSpoofDetector()

    responder_chain = [
        AlertResponder(),
        LogResponder("attack_log.txt"),
        ArpRestorationResponder()
    ]

    if args.deception:
        print("[Config] Active defense ENABLED - honeytokens will be injected")
        responder_chain.append(
            DeceptionResponder(
                beacon_domain=args.beacon,
                injection_count=10
            )
        )

    responder = CompositeResponder(responder_chain)

    system = DefenseSystem(
        detector=detector,
        responder=responder,
        listen_ip=None,
        continuous=True
    )

    try:
        system.start()
    except PermissionError:
        print("[Error] Run as Administrator/root")
    except Exception as e:
        print(f"[Error] {e}")


if __name__ == "__main__":
    main()