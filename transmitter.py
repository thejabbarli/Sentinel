import time
import threading
import random
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sendp

from config import Config
from interfaces import IResponder
from payload_manager import PayloadManager


class HoneypotTransmitter(IResponder):
    """
    Responsible for the 'Counter-Op':
    Broadcasting the fake data while pretending it's a private unicast.
    """

    def __init__(self):
        self.payload_mgr = PayloadManager()
        self.payload_mgr.ensure_payload_exists()

    def execute(self):
        print("\n[!!!] COUNTER-MEASURE INITIATED [!!!]")
        print(f"[Responder] Flooding network with disinformation...")

        # Run in a separate thread to avoid blocking the main process
        t = threading.Thread(target=self._transmission_loop)
        t.daemon = True
        t.start()

    def _transmission_loop(self):
        try:
            with self.payload_mgr.get_payload_reader() as f:
                while True:
                    chunk = f.read(50)
                    if not chunk:
                        break

                    self._send_deceptive_packet(chunk)
                    # Fast transmission
                    time.sleep(0.1)
            print("[Responder] Disinformation package delivered.")
        except Exception as e:
            print(f"[Error] Transmission failed: {e}")

    def _send_deceptive_packet(self, data_chunk):
        # Layer 2: Broadcast (So the Attacker sees it)
        eth = Ether(dst=Config.BROADCAST_MAC)
        # Layer 3: Deception (Looks like private internet traffic)
        ip = IP(dst=Config.FAKE_SRC_IP)
        # Layer 4: TCP
        tcp = TCP(sport=random.randint(1024, 65535), dport=80, flags="PA")

        pkt = eth / ip / tcp / Raw(load=data_chunk)
        sendp(pkt, verbose=0)