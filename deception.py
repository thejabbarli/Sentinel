import time
import random
import threading
import uuid
import json
from datetime import datetime
from typing import Optional

from scapy.all import conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send

from interfaces import IResponder, ThreatInfo


class DeceptionResponder(IResponder):
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
        self.gateway_ip = self._get_gateway()

    def _get_gateway(self) -> str:
        try:
            return conf.route.route("0.0.0.0")[2]
        except:
            return "8.8.8.8"

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
            time.sleep(random.uniform(0.3, 1.0))

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
        except IOError:
            pass

    def _send_deceptive_packet(self, token: dict, threat: ThreatInfo):
        external_servers = [
            "93.184.216.34",
            "151.101.1.69",
            "172.217.14.206",
            "13.107.42.14",
            "52.94.236.248",
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
            send(pkt, iface=self.interface, verbose=0)
        except Exception as e:
            print(f"[Deception] Send failed: {e}")

    def get_active_tokens(self) -> list:
        return self.active_tokens.copy()