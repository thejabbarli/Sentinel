import sys
from scapy.all import sniff, get_if_list, get_if_addr, conf
from interfaces import IAttackDetector, IResponder


class DefenseSystem:
    """
    The Main Controller.
    Injects dependencies and manages the lifecycle.
    """

    def __init__(self, detector: IAttackDetector, responder: IResponder, listen_ip="192.168.0.104"):
        self.detector = detector
        self.responder = responder
        self.listen_ip = listen_ip
        self.is_active = False

    def start_surveillance(self):
        # We need access to the port for the log message,
        # but since we rely on the abstract interface, we check if it has the attribute.
        port_info = getattr(self.detector, 'port', 'Unknown')

        # Auto-detect the correct interface for the specific IP
        # This handles the complexity of having VMware + VPN + WiFi adapters
        target_iface = self._find_interface_for_ip(self.listen_ip)

        if target_iface:
            print(f"[System] Locked onto Interface: {target_iface} (IP: {self.listen_ip})")
        else:
            print(f"[Warning] Could not find interface for {self.listen_ip}. Using Scapy default.")
            target_iface = None

        print(f"[System] Surveillance Active. Tripwire set on Port {port_info}")

        self.is_active = True
        # Sniff only TCP packets to reduce noise
        # We explicitly pass 'iface' to ensure we listen on the right adapter
        sniff(filter="arp", iface=target_iface, prn=self._traffic_handler, store=0)

    def _find_interface_for_ip(self, target_ip):
        """Helper to find the interface name associated with a specific IP."""
        try:
            for iface in get_if_list():
                if get_if_addr(iface) == target_ip:
                    return iface
        except Exception as e:
            print(f"[Debug] Error finding interface: {e}")
        return None

    def _traffic_handler(self, packet):
        if not self.is_active:
            return

        # 1. Analyze
        is_attack = self.detector.analyze_packet(packet)

        # 2. Respond
        if is_attack:
            self.responder.execute()
            self.is_active = False
            print("[System] Entering Standby mode (Response Sent). Restart script to reset.")
            sys.exit(0)