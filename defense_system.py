from typing import Optional

from scapy.all import sniff, get_if_list, get_if_addr

from interfaces import IDetector, IResponder


class DefenseSystem:
    def __init__(
            self,
            detector: IDetector,
            responder: IResponder,
            listen_ip: Optional[str] = None,
            continuous: bool = True
    ):
        self.detector = detector
        self.responder = responder
        self.listen_ip = listen_ip
        self.continuous = continuous
        self.running = False
        self.threats_detected = 0

    def start(self):
        iface = self._resolve_interface()

        print(f"[System] Starting ARP surveillance")
        if iface:
            print(f"[System] Interface: {iface}")
        else:
            print("[System] Using default interface")

        self.running = True

        try:
            sniff(
                filter="arp",
                iface=iface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except KeyboardInterrupt:
            print("\n[System] Stopped by user")
        finally:
            self._print_summary()

    def stop(self):
        self.running = False

    def _process_packet(self, packet):
        threat = self.detector.analyze(packet)

        if threat is None:
            return

        self.threats_detected += 1
        self.responder.respond(threat)

        if not self.continuous:
            self.running = False

    def _resolve_interface(self) -> Optional[str]:
        if not self.listen_ip:
            return None

        try:
            for iface in get_if_list():
                if get_if_addr(iface) == self.listen_ip:
                    return iface
        except Exception:
            pass

        return None

    def _print_summary(self):
        print(f"\n[System] Session ended. Threats detected: {self.threats_detected}")