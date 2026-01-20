import sys
from datetime import datetime
from typing import Optional

from scapy.layers.l2 import ARP, getmacbyip
from scapy.config import conf

from interfaces import IDetector, ThreatInfo


class ArpSpoofDetector(IDetector):
    def __init__(self, gateway_ip: Optional[str] = None):
        self.gateway_ip = gateway_ip or self._detect_gateway()
        self.legitimate_mac = self._resolve_mac(self.gateway_ip)

        print(f"[Detector] Initialized")
        print(f"  Gateway: {self.gateway_ip}")
        print(f"  MAC:     {self.legitimate_mac}")

    def analyze(self, packet) -> Optional[ThreatInfo]:
        if not packet.haslayer(ARP):
            return None

        arp = packet[ARP]
        if arp.op != 2:
            return None

        if arp.psrc != self.gateway_ip:
            return None

        if arp.hwsrc == self.legitimate_mac:
            return None

        return ThreatInfo(
            threat_type="ARP_SPOOFING",
            source_ip=arp.psrc,
            source_mac=arp.hwsrc,
            expected_mac=self.legitimate_mac,
            timestamp=datetime.now().isoformat(),
            raw_packet=packet
        )

    def _detect_gateway(self) -> str:
        try:
            return conf.route.route("0.0.0.0")[2]
        except Exception:
            print("[Error] Cannot detect gateway. Check network connection.")
            sys.exit(1)

    def _resolve_mac(self, ip: str) -> str:
        mac = getmacbyip(ip)
        if not mac:
            print(f"[Error] Cannot resolve MAC for {ip}")
            sys.exit(1)
        return mac