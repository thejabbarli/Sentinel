import sys
# UPDATED: Import getmacbyip specifically from layers.l2 to fix PyCharm reference error
from scapy.layers.l2 import ARP, getmacbyip
from scapy.config import conf
from interfaces import IAttackDetector


class ArpSpoofDetector(IAttackDetector):
    """
    Detects ARP Cache Poisoning (MITM Attacks).
    It memorizes the Gateway's real MAC address and screams if it changes.
    """

    def __init__(self):
        self.gateway_ip = self._get_default_gateway()
        self.real_mac = self._get_mac(self.gateway_ip)

        print(f"[Detector] Calibration Complete.")
        print(f"           Gateway IP:  {self.gateway_ip}")
        print(f"           Real MAC:    {self.real_mac}")

    def analyze_packet(self, packet):
        # We only care about ARP Packets
        if packet.haslayer(ARP):
            # op=2 means it is an ARP "Reply" (Response)
            # This is the packet attackers spoof: "Hey, I am the router!"
            if packet[ARP].op == 2:
                # Check if the packet claims to be from the Gateway
                if packet[ARP].psrc == self.gateway_ip:
                    # CHECK: Does the MAC address match the real one?
                    claimed_mac = packet[ARP].hwsrc
                    if claimed_mac != self.real_mac:
                        print(f"[!!!] MITM DETECTED [!!!]")
                        print(f"      Real Gateway MAC: {self.real_mac}")
                        print(f"      Spoofed MAC:      {claimed_mac}")
                        return True
        return False

    def _get_default_gateway(self):
        """Auto-detects the Router IP."""
        try:
            # Scapy's internal routing table
            # route("0.0.0.0") returns (interface, output_ip, gateway_ip)
            return conf.route.route("0.0.0.0")[2]
        except:
            print("[Error] Could not find Gateway IP. Check connection.")
            sys.exit(1)

    def _get_mac(self, ip):
        """Resolves the physical MAC address for an IP."""
        mac = getmacbyip(ip)
        if not mac:
            print(f"[Error] Could not resolve MAC for {ip}. Network might be down.")
            sys.exit(1)
        return mac