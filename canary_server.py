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
import logging
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional


alert_logger = logging.getLogger("canary_alerts")


def setup_logging(log_file: str, console: bool = True):
    """Configure logging for canary alerts."""
    alert_logger.setLevel(logging.INFO)
    

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    alert_logger.addHandler(file_handler)
    

    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('[ALERT] %(message)s'))
        alert_logger.addHandler(console_handler)


class CanaryHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs all requests as potential attacker activity."""
    
    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_HEAD(self):
        self._handle_request("HEAD")

    def do_OPTIONS(self):
        self._handle_request("OPTIONS")

    def _handle_request(self, method: str):
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        timestamp = datetime.now().isoformat()
        user_agent = self.headers.get("User-Agent", "Unknown")
        

        token_id = self._extract_token_id(self.path)


        content_length = self.headers.get('Content-Length')
        body = None
        if content_length and method in ("POST", "PUT"):
            try:
                body = self.rfile.read(int(content_length)).decode('utf-8', errors='replace')
            except Exception:
                body = "<read error>"

        alert = {
            "timestamp": timestamp,
            "attacker_ip": client_ip,
            "attacker_port": client_port,
            "method": method,
            "path": self.path,
            "token_id": token_id,
            "user_agent": user_agent,
            "headers": dict(self.headers),
            "body": body
        }


        alert_logger.info(json.dumps(alert))


        self._print_alert(alert)


        self._send_response(method)

    def _extract_token_id(self, path: str) -> Optional[str]:
        """Extract token ID from common path patterns."""

        parts = path.strip('/').split('/')
        if len(parts) >= 2:
            return parts[-1]
        return None

    def _print_alert(self, alert: dict):
        """Print a visually distinct alert to console."""
        print("\n" + "=" * 60)
        print("  🚨 HONEYTOKEN TRIGGERED - ATTACKER CAUGHT 🚨")
        print("=" * 60)
        print(f"  Time:        {alert['timestamp']}")
        print(f"  Attacker IP: {alert['attacker_ip']}:{alert['attacker_port']}")
        print(f"  Method:      {alert['method']}")
        print(f"  Path:        {alert['path']}")
        if alert['token_id']:
            print(f"  Token ID:    {alert['token_id']}")
        print(f"  User-Agent:  {alert['user_agent']}")
        print("=" * 60 + "\n")

    def _send_response(self, method: str):
        """Send a response that looks legitimate to avoid tipping off attacker."""
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Server", "nginx")  # Blend in
        self.end_headers()


        if method != "HEAD":
            response = {"status": "ok", "message": "Request processed"}
            self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        """Suppress default HTTP logging - we use our own."""
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Canary Server for Honeytoken Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python canary_server.py                    # Listen on port 80
    python canary_server.py --port 8080        # Custom port
    python canary_server.py --log alerts.jsonl # Custom log file
        """
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=80, 
        help="Port to listen on (default: 80)"
    )
    parser.add_argument(
        "--host", 
        type=str, 
        default="0.0.0.0", 
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--log",
        type=str,
        default="canary_alerts.jsonl",
        help="Log file for alerts (default: canary_alerts.jsonl)"
    )
    args = parser.parse_args()

    setup_logging(args.log)

    try:
        server = HTTPServer((args.host, args.port), CanaryHandler)
    except PermissionError:
        print(f"[Error] Cannot bind to port {args.port} - try running as root or use --port 8080")
        sys.exit(1)
    except OSError as e:
        print(f"[Error] Cannot start server: {e}")
        sys.exit(1)

    print(f"[Canary] Server started on {args.host}:{args.port}")
    print(f"[Canary] Alerts logging to: {args.log}")
    print(f"[Canary] Waiting for attackers to use stolen honeytokens...")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Canary] Shutting down...")
        server.shutdown()
        print("[Canary] Server stopped")


if __name__ == "__main__":
    main()
