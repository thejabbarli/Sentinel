import subprocess
import platform
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
        if not threat.expected_mac:
            print("[Defense] Cannot restore ARP - no expected MAC available")
            return False

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
        except PermissionError:
            print("[Defense] Restoration failed: need root/admin privileges")
            return False
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
        except FileNotFoundError:
            pass  # netsh not available
        except Exception:
            pass


class CompositeResponder(IResponder):
    """
    Executes multiple responders in sequence.
    
    Design decision: Returns True if ANY responder succeeds.
    Rationale: We want alerting/logging to work even if ARP restoration fails.
    Each responder failure is logged individually.
    """

    def __init__(self, responders: List[IResponder], fail_fast: bool = False):
        """
        Args:
            responders: List of responders to execute
            fail_fast: If True, stops on first failure. If False (default),
                      runs all responders regardless of individual failures.
        """
        self.responders = responders
        self.fail_fast = fail_fast

    def respond(self, threat: ThreatInfo) -> bool:
        if not self.responders:
            return True

        results = []
        for responder in self.responders:
            try:
                result = responder.respond(threat)
                results.append(result)
                
                if not result and self.fail_fast:
                    print(f"[Composite] {type(responder).__name__} failed, stopping chain")
                    break
                    
            except Exception as e:
                print(f"[Composite] {type(responder).__name__} raised exception: {e}")
                results.append(False)
                
                if self.fail_fast:
                    break

        # Success if at least one responder worked
        return any(results)
