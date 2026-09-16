#!/usr/bin/env python3
"""
api_server.py
AI-Powered Threat Detection System
Minimal stdlib HTTP API for the alert triage engine.
POST /triage with an alert JSON body -> triage result.
"""

import os
import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from triage_engine import AlertTriageEngine

engine = AlertTriageEngine(config_path="config/triage_config.json")


class TriageHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self._send(200, {"service": "alert-triage", "status": "ok"})

    def do_POST(self):
        if self.path != "/triage":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            alert = json.loads(self.rfile.read(length))
            self._send(200, asdict(engine.triage_alert(alert)))
        except json.JSONDecodeError as e:
            self._send(400, {"error": f"invalid JSON: {e}"})

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.getenv("TRIAGE_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), TriageHandler).serve_forever()