import sys
from scapy.all import sniff
from interfaces import IAttackDetector, IResponder


class DefenseSystem:
    """
    The Main Controller.
    Injects dependencies and manages the lifecycle.
    """

    def __init__(self, detector: IAttackDetector, responder: IResponder):
        self.detector = detector
        self.responder = responder
        self.is_active = False

    def start_surveillance(self):
        # We need access to the port for the log message,
        # but since we rely on the abstract interface, we check if it has the attribute.
        port_info = getattr(self.detector, 'port', 'Unknown')
        print(f"[System] Surveillance Active. Tripwire set on Port {port_info}")

        self.is_active = True
        # Sniff only TCP packets to reduce noise
        sniff(filter="tcp", prn=self._traffic_handler, store=0)

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