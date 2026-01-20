"""
Setup and Configuration Script

Automatically detects network configuration and helps users set up the defense system.

Usage:
    python setup.py
    python setup.py --check
"""

import sys
import subprocess
import socket
import platform

try:
    from scapy.all import get_if_list, get_if_addr, conf
    from scapy.layers.l2 import getmacbyip

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def check_dependencies():
    print_header("Checking Dependencies")

    issues = []

    if not SCAPY_AVAILABLE:
        issues.append("Scapy not installed. Run: pip install scapy")
        print("  [FAIL] Scapy")
    else:
        print("  [OK] Scapy")

    if platform.system() == "Windows":
        try:
            import winreg
            print("  [OK] Windows environment")
        except:
            pass

        try:
            result = subprocess.run(
                ["where", "npcap"],
                capture_output=True,
                text=True
            )
        except:
            pass

    return len(issues) == 0, issues


def check_privileges():
    print_header("Checking Privileges")

    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
    else:
        is_admin = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False

    if is_admin:
        print("  [OK] Running with administrator/root privileges")
    else:
        print("  [WARN] Not running as administrator/root")
        print("         The defense system requires elevated privileges")

    return is_admin


def detect_network():
    print_header("Network Configuration")

    if not SCAPY_AVAILABLE:
        print("  [SKIP] Scapy not available")
        return None

    try:
        gateway_ip = conf.route.route("0.0.0.0")[2]
        print(f"  Gateway IP:  {gateway_ip}")
    except Exception as e:
        print(f"  [FAIL] Cannot detect gateway: {e}")
        return None

    try:
        gateway_mac = getmacbyip(gateway_ip)
        print(f"  Gateway MAC: {gateway_mac}")
    except Exception as e:
        print(f"  [WARN] Cannot resolve gateway MAC: {e}")
        gateway_mac = None

    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        for iface in get_if_list():
            addr = get_if_addr(iface)
            if addr and not addr.startswith("127."):
                local_ip = addr
                break

        print(f"  Local IP:    {local_ip}")
    except Exception as e:
        print(f"  [WARN] Cannot detect local IP: {e}")
        local_ip = None

    print_header("Available Interfaces")

    try:
        for iface in get_if_list():
            addr = get_if_addr(iface)
            if addr:
                print(f"  {iface}: {addr}")
    except Exception as e:
        print(f"  [FAIL] Cannot list interfaces: {e}")

    return {
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "local_ip": local_ip
    }


def print_usage_instructions(network_info):
    print_header("How to Use")

    print("""
  BASIC USAGE (Detection + Passive Defense):

    Windows (Admin Command Prompt):
      python main.py

    Linux/Mac:
      sudo python main.py

  WITH ACTIVE DEFENSE (Honeytokens):

    python main.py --deception

  WITH CUSTOM BEACON DOMAIN:

    python main.py --deception --beacon your-canary-domain.com
    """)

    print_header("Testing with Kali Linux")

    if network_info:
        local_ip = network_info.get("local_ip", "<your_ip>")
        gateway_ip = network_info.get("gateway_ip", "<gateway_ip>")
    else:
        local_ip = "<your_ip>"
        gateway_ip = "<gateway_ip>"

    print(f"""
  On Kali (attacker), run:

    sudo arpspoof -i eth0 -t {local_ip} {gateway_ip}

  To capture honeytokens on Kali:

    sudo tcpdump -i eth0 -A | grep -E "(API_KEY|Password|aws_)"
    """)


def print_test_instructions():
    print_header("Local Testing (Without Kali)")

    print("""
  You can test detection using the included test script:

    Terminal 1 (Defense):
      python main.py --deception

    Terminal 2 (Simulate Attack):
      python test_detection.py
    """)


def main():
    import os

    print("\n")
    print("  ARP Defense System - Setup")
    print("  " + "=" * 40)

    deps_ok, issues = check_dependencies()

    if not deps_ok:
        print("\n[!] Please fix the following issues:")
        for issue in issues:
            print(f"    - {issue}")
        sys.exit(1)

    check_privileges()

    network_info = detect_network()

    print_usage_instructions(network_info)
    print_test_instructions()

    print_header("Ready")
    print("  Your system is configured. Run 'python main.py' to start.\n")


if __name__ == "__main__":
    main()