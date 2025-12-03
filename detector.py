from scapy.layers.inet import TCP, IP
from interfaces import IAttackDetector

class TripwireDetector(IAttackDetector):
    """
    Detects an attack if a specific 'Bait Port' is touched.
    """
    def __init__(self, port):
        self.port = port

    def analyze_packet(self, packet):
        # Check if packet is TCP and destination port matches tripwire
        if packet.haslayer(TCP):
            if packet[TCP].dport == self.port:
                src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                print(f"[Detector] TRIPWIRE TRIGGERED on Port {self.port} from {src_ip}")
                return True
        return False