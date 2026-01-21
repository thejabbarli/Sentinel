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
        except PermissionError:
            print("[System] Permission denied - run as root/administrator")
            raise
        finally:
            self._print_summary()

    def stop(self):
        self.running = False

    def _process_packet(self, packet):
        try:
            threat = self.detector.analyze(packet)
        except Exception as e:
            print(f"[System] Detector error: {e}")
            return

        if threat is None:
            return

        self.threats_detected += 1
        
        try:
            self.responder.respond(threat)
        except Exception as e:
            print(f"[System] Responder error: {e}")

        if not self.continuous:
            self.running = False

    def _resolve_interface(self) -> Optional[str]:
        """
        Resolve network interface from listen_ip.
        Returns None if no listen_ip specified or interface not found.
        """
        if not self.listen_ip:
            return None

        try:
            interfaces = get_if_list()
            for iface in interfaces:
                try:
                    addr = get_if_addr(iface)
                    if addr == self.listen_ip:
                        return iface
                except (OSError, ValueError):
                    # Some interfaces may not have valid addresses
                    continue
                    
        except OSError as e:
            print(f"[System] Warning: Failed to enumerate interfaces: {e}")
        except ImportError as e:
            print(f"[System] Warning: Scapy interface functions unavailable: {e}")

        if self.listen_ip:
            print(f"[System] Warning: No interface found for IP {self.listen_ip}")
        
        return None

    def _print_summary(self):
        print(f"\n[System] Session ended. Threats detected: {self.threats_detected}")
