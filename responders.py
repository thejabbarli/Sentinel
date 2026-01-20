import os
import subprocess
import platform
from datetime import datetime
from typing import List

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp

from interfaces import IResponder, ThreatInfo


class LogResponder(IResponder):
    def __init__(self, log_path: str = "defense_log.txt"):
        self.log_path = log_path

    def respond(self, threat: ThreatInfo) -> bool:
        entry = (
            f"[{threat.timestamp}] "
            f"THREAT: {threat.threat_type} | "
            f"Attacker MAC: {threat.source_mac} | "
            f"Spoofed IP: {threat.source_ip} | "
            f"Expected MAC: {threat.expected_mac}\n"
        )
        try:
            with open(self.log_path, "a") as f:
                f.write(entry)
            return True
        except IOError as e:
            print(f"[Log] Write failed: {e}")
            return False


class AlertResponder(IResponder):
    def respond(self, threat: ThreatInfo) -> bool:
        print("\n" + "=" * 60)
        print("  ⚠️  ARP SPOOFING ATTACK DETECTED  ⚠️")
        print("=" * 60)
        print(f"  Time:         {threat.timestamp}")
        print(f"  Attacker MAC: {threat.source_mac}")
        print(f"  Target IP:    {threat.source_ip}")
        print(f"  Real MAC:     {threat.expected_mac}")
        print("=" * 60 + "\n")
        return True


class ArpRestorationResponder(IResponder):
    def __init__(self, interface: str = None, restore_count: int = 5):
        self.interface = interface
        self.restore_count = restore_count

    def respond(self, threat: ThreatInfo) -> bool:
        print("[Defense] Attempting ARP table restoration...")

        success = self._send_correction_packets(threat)

        if platform.system() == "Windows":
            self._flush_arp_cache_windows()

        return success

    def _send_correction_packets(self, threat: ThreatInfo) -> bool:
        try:
            correct_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                psrc=threat.source_ip,
                hwsrc=threat.expected_mac,
                pdst=threat.source_ip,
                hwdst="ff:ff:ff:ff:ff:ff"
            )

            for _ in range(self.restore_count):
                sendp(correct_arp, iface=self.interface, verbose=0)

            print(f"[Defense] Sent {self.restore_count} corrective ARP packets")
            return True
        except Exception as e:
            print(f"[Defense] Restoration failed: {e}")
            return False

    def _flush_arp_cache_windows(self):
        try:
            subprocess.run(
                ["netsh", "interface", "ip", "delete", "arpcache"],
                capture_output=True,
                check=False
            )
            print("[Defense] Requested ARP cache flush")
        except Exception:
            pass


class CompositeResponder(IResponder):
    def __init__(self, responders: List[IResponder]):
        self.responders = responders

    def respond(self, threat: ThreatInfo) -> bool:
        results = [r.respond(threat) for r in self.responders]
        return all(results)