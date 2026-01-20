"""
Canary Server - Catches attackers who use stolen honeytokens

Run this on a machine accessible from the internet (or your local network for testing).
When an attacker uses a captured honeytoken, they'll hit this server and you'll know.

Usage:
    python canary_server.py
    python canary_server.py --port 8080
"""

import argparse
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler


class CanaryHandler(BaseHTTPRequestHandler):
    log_file = "canary_alerts.txt"

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def _handle_request(self, method):
        client_ip = self.client_address[0]
        timestamp = datetime.now().isoformat()
        user_agent = self.headers.get("User-Agent", "Unknown")

        alert = {
            "timestamp": timestamp,
            "attacker_ip": client_ip,
            "method": method,
            "path": self.path,
            "user_agent": user_agent,
            "headers": dict(self.headers)
        }

        print("\n" + "=" * 60)
        print("  🚨 HONEYTOKEN TRIGGERED - ATTACKER CAUGHT 🚨")
        print("=" * 60)
        print(f"  Time:        {timestamp}")
        print(f"  Attacker IP: {client_ip}")
        print(f"  Path:        {self.path}")
        print(f"  User-Agent:  {user_agent}")
        print("=" * 60 + "\n")

        with open(self.log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()

        response = {"status": "ok", "message": "Request processed"}
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description="Canary Server for Honeytoken Detection")
    parser.add_argument("--port", type=int, default=80, help="Port to listen on (default: 80)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), CanaryHandler)

    print(f"[Canary] Server started on {args.host}:{args.port}")
    print(f"[Canary] Waiting for attackers to use stolen honeytokens...")
    print(f"[Canary] Alerts will be logged to canary_alerts.txt")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Canary] Server stopped")
        server.shutdown()


if __name__ == "__main__":
    main()