import time
import random
import threading
import uuid
import json
from datetime import datetime
from typing import Optional

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sendp

from interfaces import IResponder, ThreatInfo


class DeceptionResponder(IResponder):
    """
    Active defense through cyber deception.

    When an attack is detected, this responder injects honeytokens into
    network traffic. These are fake credentials/data that look valuable
    but are actually traps. If an attacker uses them:

    1. Beacon URLs - HTTP requests to your canary server expose attacker IP
    2. Fake API keys - Trigger alerts when used against your services
    3. Decoy credentials - Lead to honeypot systems that log everything

    The goal: Make attackers uncertain if captured data is real or a trap.
    This increases attack cost and creates deterrence.
    """

    def __init__(
            self,
            interface: Optional[str] = None,
            beacon_domain: str = "canary.yourdomain.com",
            injection_count: int = 10,
            log_path: str = "deception_log.txt"
    ):
        self.interface = interface
        self.beacon_domain = beacon_domain
        self.injection_count = injection_count
        self.log_path = log_path
        self.active_tokens = []

    def respond(self, threat: ThreatInfo) -> bool:
        print("\n[Deception] Initiating active defense...")
        print(f"[Deception] Injecting {self.injection_count} honeytokens into traffic")

        thread = threading.Thread(target=self._inject_honeytokens, args=(threat,))
        thread.daemon = True
        thread.start()

        return True

    def _inject_honeytokens(self, threat: ThreatInfo):
        for i in range(self.injection_count):
            token = self._generate_honeytoken()
            self._log_token(token)
            self._send_deceptive_packet(token, threat)
            time.sleep(random.uniform(0.5, 2.0))

        print(f"[Deception] Injection complete. {self.injection_count} honeytokens deployed.")
        print(f"[Deception] Tokens logged to {self.log_path}")

    def _generate_honeytoken(self) -> dict:
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
            f"# Production API Configuration\n"
            f"API_KEY=sk_live_{token_id}_{''.join(random.choices('abcdef0123456789', k=24))}\n"
            f"API_SECRET={''.join(random.choices('ABCDEFGHIJKLMNOP0123456789', k=32))}\n"
            f"WEBHOOK_URL=http://{self.beacon_domain}/webhook/{token_id}\n"
        )

    def _gen_fake_credentials(self, token_id: str) -> str:
        return (
            f"Host: internal-db.corp.local\n"
            f"Username: svc_admin_{token_id}\n"
            f"Password: Pr0d#{''.join(random.choices('abcdefghijkmnpqrstuvwxyz23456789', k=12))}\n"
            f"Verify at: http://{self.beacon_domain}/verify/{token_id}\n"
        )

    def _gen_fake_config(self, token_id: str) -> str:
        return json.dumps({
            "aws_access_key": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
            "aws_secret_key": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/', k=40))}",
            "s3_bucket": f"backup-{token_id}-prod",
            "health_check": f"http://{self.beacon_domain}/health/{token_id}"
        }, indent=2)

    def _gen_fake_db_connection(self, token_id: str) -> str:
        return (
            f"mongodb://admin_user:{''.join(random.choices('abcdefghijkmnpqrstuvwxyz23456789', k=16))}"
            f"@db-{token_id}.internal:27017/production?authSource=admin\n"
            f"# Backup: http://{self.beacon_domain}/db/{token_id}\n"
        )

    def _log_token(self, token: dict):
        self.active_tokens.append(token)

        entry = (
            f"[{token['created']}] "
            f"HONEYTOKEN DEPLOYED | "
            f"ID: {token['id']} | "
            f"Type: {token['type']} | "
            f"Beacon: {token['beacon_url']}\n"
        )

        try:
            with open(self.log_path, "a") as f:
                f.write(entry)
        except IOError:
            pass

    def _send_deceptive_packet(self, token: dict, threat: ThreatInfo):
        fake_dst_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        eth = Ether(dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="192.168.1.100", dst=fake_dst_ip)
        tcp = TCP(
            sport=random.randint(49152, 65535),
            dport=random.choice([80, 443, 8080, 3306, 5432, 27017]),
            flags="PA"
        )

        payload = token["data"]
        if isinstance(payload, str):
            payload = payload.encode()

        pkt = eth / ip / tcp / Raw(load=payload)

        try:
            sendp(pkt, iface=self.interface, verbose=0)
        except Exception as e:
            print(f"[Deception] Packet injection failed: {e}")

    def get_active_tokens(self) -> list:
        return self.active_tokens.copy()