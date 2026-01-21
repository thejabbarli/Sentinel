import time
import random
import threading
import uuid
import json
import logging
from datetime import datetime
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, Future

from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send

from interfaces import IResponder, ThreatInfo


# Configure module logger
logger = logging.getLogger(__name__)


class DeceptionResponder(IResponder):
    """
    Active defense responder that injects honeytokens into network traffic.
    
    When an attack is detected, injects fake credentials containing tracking
    beacons. If an attacker uses these credentials, they hit your canary server.
    """

    def __init__(
            self,
            interface: Optional[str] = None,
            beacon_domain: str = "canary.yourdomain.com",
            injection_count: int = 10,
            log_path: str = "deception_log.txt",
            async_mode: bool = True
    ):
        """
        Args:
            interface: Network interface to send packets on (None for default)
            beacon_domain: Domain/IP for tracking beacons
            injection_count: Number of honeytokens to inject per attack
            log_path: File to log generated tokens
            async_mode: If True, inject in background thread. If False, block until done.
        """
        self.interface = interface
        self.beacon_domain = beacon_domain
        self.injection_count = injection_count
        self.log_path = log_path
        self.async_mode = async_mode
        self.active_tokens: List[dict] = []
        self._lock = threading.Lock()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._pending_futures: List[Future] = []
        
        # Validate beacon domain
        if not beacon_domain or len(beacon_domain) < 3:
            raise ValueError("beacon_domain must be a valid domain or IP")

    def respond(self, threat: ThreatInfo) -> bool:
        print("\n[Deception] Initiating active defense...")
        print(f"[Deception] Injecting {self.injection_count} honeytokens into traffic")

        if self.async_mode:
            return self._respond_async(threat)
        else:
            return self._respond_sync(threat)

    def _respond_sync(self, threat: ThreatInfo) -> bool:
        """Synchronous injection - blocks until complete."""
        try:
            self._inject_honeytokens(threat)
            return True
        except Exception as e:
            print(f"[Deception] Injection failed: {e}")
            logger.exception("Honeytoken injection failed")
            return False

    def _respond_async(self, threat: ThreatInfo) -> bool:
        """Asynchronous injection - returns immediately, runs in background."""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="deception")

        def _injection_task():
            try:
                self._inject_honeytokens(threat)
            except Exception as e:
                print(f"[Deception] Background injection failed: {e}")
                logger.exception("Background honeytoken injection failed")

        future = self._executor.submit(_injection_task)
        
        with self._lock:
            # Clean up completed futures
            self._pending_futures = [f for f in self._pending_futures if not f.done()]
            self._pending_futures.append(future)

        return True  # Submission succeeded; actual injection is async

    def _inject_honeytokens(self, threat: ThreatInfo):
        """Core injection logic - generates and sends honeytokens."""
        successful = 0
        failed = 0

        for i in range(self.injection_count):
            try:
                token = self._generate_honeytoken()
                self._log_token(token)
                self._send_deceptive_packet(token, threat)
                successful += 1
            except Exception as e:
                failed += 1
                logger.warning(f"Token injection {i+1} failed: {e}")
            
            # Random delay between injections
            time.sleep(random.uniform(0.3, 1.0))

        print(f"[Deception] Injection complete. Success: {successful}, Failed: {failed}")
        print(f"[Deception] Tokens logged to {self.log_path}")

    def _generate_honeytoken(self) -> dict:
        """Generate a unique honeytoken with embedded tracking beacon."""
        token_id = str(uuid.uuid4())[:8]
        token_type = random.choice(["api_key", "credentials", "config", "database"])

        generators = {
            "api_key": self._gen_fake_api_key,
            "credentials": self._gen_fake_credentials,
            "config": self._gen_fake_config,
            "database": self._gen_fake_db_connection
        }

        token_data = generators[token_type](token_id)

        return {
            "id": token_id,
            "type": token_type,
            "data": token_data,
            "created": datetime.now().isoformat(),
            "beacon_url": f"http://{self.beacon_domain}/t/{token_id}"
        }

    def _gen_fake_api_key(self, token_id: str) -> str:
        return (
            f"API_KEY=sk_live_{token_id}_{''.join(random.choices('abcdef0123456789', k=24))}\n"
            f"API_SECRET={''.join(random.choices('ABCDEFGHIJKLMNOP0123456789', k=32))}\n"
            f"WEBHOOK=http://{self.beacon_domain}/hook/{token_id}\n"
        )

    def _gen_fake_credentials(self, token_id: str) -> str:
        return (
            f"Username: admin_{token_id}\n"
            f"Password: Pr0d#{''.join(random.choices('abcdefghijkmnpqrstuvwxyz23456789', k=12))}\n"
            f"Portal: http://{self.beacon_domain}/login/{token_id}\n"
        )

    def _gen_fake_config(self, token_id: str) -> str:
        return json.dumps({
            "aws_access_key": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
            "aws_secret": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEF0123456789', k=40))}",
            "endpoint": f"http://{self.beacon_domain}/aws/{token_id}"
        })

    def _gen_fake_db_connection(self, token_id: str) -> str:
        return (
            f"mongodb://root:{''.join(random.choices('abcdefghijkmnpqrstuvwxyz23456789', k=16))}"
            f"@db.internal:27017/prod\n"
            f"http://{self.beacon_domain}/db/{token_id}\n"
        )

    def _log_token(self, token: dict):
        """Thread-safe token logging."""
        with self._lock:
            self.active_tokens.append(token)

        entry = (
            f"[{token['created']}] "
            f"ID: {token['id']} | "
            f"Type: {token['type']} | "
            f"Beacon: {token['beacon_url']}\n"
        )

        try:
            with open(self.log_path, "a") as f:
                f.write(entry)
        except IOError as e:
            logger.warning(f"Failed to write token log: {e}")

    def _send_deceptive_packet(self, token: dict, threat: ThreatInfo):
        """Send a packet containing the honeytoken data."""

        external_servers = [
            "93.184.216.34",    # example.com
            "151.101.1.69",     # reddit
            "172.217.14.206",   # google
            "13.107.42.14",     # microsoft
            "52.94.236.248",    # aws
        ]

        fake_dst = random.choice(external_servers)

        payload = token["data"]
        if isinstance(payload, str):
            payload = payload.encode()

        pkt = IP(dst=fake_dst) / TCP(
            sport=random.randint(49152, 65535),
            dport=random.choice([80, 443, 8080]),
            flags="PA",
            seq=random.randint(1000, 9999999)
        ) / Raw(load=payload)

        try:
             send(pkt, verbose=0)
        except PermissionError:
            raise PermissionError("Need root/admin to send packets")
        except Exception as e:
            raise RuntimeError(f"Packet send failed: {e}")

    def get_active_tokens(self) -> List[dict]:
        """Return a copy of all generated tokens (thread-safe)."""
        with self._lock:
            return self.active_tokens.copy()

    def shutdown(self):
        """Clean shutdown - wait for pending injections to complete."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None
