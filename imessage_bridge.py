#!/usr/bin/env python3
"""
iMessage Bridge — HTTP bridge to imsg rpc.

Runs on the Mac where Messages is signed in. Manages an `imsg rpc` subprocess
and exposes its JSON-RPC interface over HTTP, with contact-based security filtering.

This lets a remote client (like the imsg_http_proxy) talk to imsg over HTTP
instead of needing direct stdio/SSH access.

Usage:
    IMSG_ALLOWED_CONTACT="+15551234567" IMSG_BRIDGE_TOKEN="secret" python3 imessage_bridge.py

Environment variables:
    IMSG_ALLOWED_CONTACT  Phone number or Apple ID email (required)
    IMSG_BRIDGE_TOKEN     Bearer token for HTTP auth (required)
    IMSG_BRIDGE_HOST      Bind address (default: 0.0.0.0)
    IMSG_BRIDGE_PORT      Listen port (default: 8788)
    IMSG_PATH             Path to imsg binary (default: /opt/homebrew/bin/imsg)
    IMSG_DB_PATH          Path to chat.db (optional, passed to imsg)

Endpoints:
    GET  /health          — Health check (no auth)
    POST /rpc             — Forward a JSON-RPC request to imsg, return response
    GET  /notifications   — Return buffered inbound notifications, clear buffer
"""

import http.server
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Config ──────────────────────────────────────────────────────────────

ALLOWED_CONTACT = os.environ.get("IMSG_ALLOWED_CONTACT", "")
BRIDGE_TOKEN = os.environ.get("IMSG_BRIDGE_TOKEN", "")
BRIDGE_HOST = os.environ.get("IMSG_BRIDGE_HOST", "0.0.0.0")
BRIDGE_PORT = int(os.environ.get("IMSG_BRIDGE_PORT", "8788"))
IMSG_PATH = os.environ.get("IMSG_PATH", "/opt/homebrew/bin/imsg")
IMSG_DB_PATH = os.environ.get("IMSG_DB_PATH", "")

# Max notifications to buffer before dropping oldest
NOTIFICATION_BUFFER_MAX = 500
# Timeout waiting for an RPC response (seconds)
RPC_TIMEOUT = 15

if not ALLOWED_CONTACT:
    print("ERROR: IMSG_ALLOWED_CONTACT is required", file=sys.stderr)
    sys.exit(1)
if not BRIDGE_TOKEN:
    print("ERROR: IMSG_BRIDGE_TOKEN is required", file=sys.stderr)
    sys.exit(1)

# ── Contact filtering ───────────────────────────────────────────────────


def normalize_handle(handle: str) -> str:
    """Normalize a phone number or email for comparison."""
    h = handle.strip().lower()
    for prefix in ("imessage:", "sms:", "tel:"):
        if h.startswith(prefix):
            h = h[len(prefix):]
    h = h.strip()
    if h.startswith("+") or (h and h[0].isdigit()) or h.startswith("("):
        digits = "".join(c for c in h if c.isdigit())
        if len(digits) == 10:
            digits = "1" + digits
        if digits:
            return "+" + digits
    return h


def is_allowed(handle: str) -> bool:
    if not handle or not ALLOWED_CONTACT:
        return False
    return normalize_handle(handle) == normalize_handle(ALLOWED_CONTACT)


def is_allowed_send(params: dict) -> bool:
    """Check if a send request targets the allowed contact."""
    to = params.get("to", "")
    if to and is_allowed(to):
        return True
    if params.get("chat_id") or params.get("chat_guid") or params.get("chat_identifier"):
        log("BLOCKED send: chat_id/chat_guid targets not allowed")
        return False
    if to:
        log(f"BLOCKED send to {to}: not in allowlist")
    return False


def extract_sender(params: dict) -> str:
    """Extract sender from a notification."""
    msg = params.get("message", params)
    if isinstance(msg, dict):
        for key in ("sender", "handle", "from", "address"):
            val = msg.get(key, "")
            if isinstance(val, str) and val.strip():
                return val.strip()
    for key in ("sender", "handle", "from", "address"):
        val = params.get(key, "")
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def is_allowed_notification(params: dict) -> bool:
    """Check if an incoming notification is from the allowed contact."""
    # Skip messages from self
    msg = params.get("message", params)
    if isinstance(msg, dict) and msg.get("is_from_me"):
        return False
    sender = extract_sender(params)
    if sender and is_allowed(sender):
        return True
    if sender:
        log(f"DROPPED notification from {sender}: not in allowlist")
    return False


# ── Logging ─────────────────────────────────────────────────────────────


def log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[bridge {ts}] {msg}", file=sys.stderr, flush=True)


# ── imsg rpc manager ───────────────────────────────────────────────────


class ImsgRpcManager:
    """Manages the imsg rpc subprocess and routes JSON-RPC traffic."""

    def __init__(self):
        self.proc = None
        self.stdin_lock = threading.Lock()
        self.pending = {}  # id -> threading.Event, result holder
        self.pending_lock = threading.Lock()
        self.notifications = []
        self.notifications_lock = threading.Lock()
        self.reader_thread = None
        self.running = False

    def start(self):
        args = [IMSG_PATH, "rpc"]
        if IMSG_DB_PATH:
            args.extend(["--db", IMSG_DB_PATH])

        try:
            self.proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                text=True,
                bufsize=1
            )
        except FileNotFoundError:
            log(f"ERROR: imsg not found at {IMSG_PATH}")
            sys.exit(1)

        self.running = True
        self.reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.reader_thread.start()
        log(f"imsg rpc started (pid {self.proc.pid})")

    def stop(self):
        self.running = False
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()
            self.proc = None

    def _read_stdout(self):
        """Read lines from imsg stdout, route to pending requests or notification buffer."""
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                msg_id = msg.get("id")

                # Response to a request
                if msg_id is not None:
                    key = str(msg_id)
                    with self.pending_lock:
                        if key in self.pending:
                            entry = self.pending[key]
                            entry["result"] = msg
                            entry["event"].set()
                            continue

                # Notification
                method = msg.get("method", "")
                params = msg.get("params", {})

                if method in ("message", "new_message", "message_received"):
                    if not is_allowed_notification(params):
                        continue

                with self.notifications_lock:
                    self.notifications.append(json.dumps(msg))
                    # Trim if too large
                    if len(self.notifications) > NOTIFICATION_BUFFER_MAX:
                        self.notifications = self.notifications[-NOTIFICATION_BUFFER_MAX:]

        except Exception as e:
            if self.running:
                log(f"stdout reader error: {e}")

    def send_request(self, request: dict, timeout: float = RPC_TIMEOUT) -> dict:
        """Send a JSON-RPC request and wait for the response."""
        if not self.proc or not self.proc.stdin:
            return {"jsonrpc": "2.0", "id": request.get("id"),
                    "error": {"code": -32000, "message": "imsg rpc not running"}}

        req_id = request.get("id")
        if req_id is None:
            # Notification from client — just forward, no response expected
            with self.stdin_lock:
                self.proc.stdin.write(json.dumps(request) + "\n")
                self.proc.stdin.flush()
            return {}

        # Security check for send requests
        method = request.get("method", "")
        params = request.get("params", {})
        if method == "send" and not is_allowed_send(params):
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32001,
                           "message": "Blocked by iMessage bridge: recipient not in allowlist"}
            }

        # Register pending response
        key = str(req_id)
        event = threading.Event()
        entry = {"event": event, "result": None}

        with self.pending_lock:
            self.pending[key] = entry

        try:
            # Send request
            with self.stdin_lock:
                self.proc.stdin.write(json.dumps(request) + "\n")
                self.proc.stdin.flush()

            # Wait for response
            if event.wait(timeout=timeout):
                return entry["result"]
            else:
                return {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32000, "message": f"Timeout waiting for response ({timeout}s)"}
                }
        finally:
            with self.pending_lock:
                self.pending.pop(key, None)

    def drain_notifications(self) -> list:
        """Return and clear buffered notifications."""
        with self.notifications_lock:
            result = self.notifications[:]
            self.notifications.clear()
        return result

    @property
    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


# ── HTTP Server ─────────────────────────────────────────────────────────

rpc_manager = ImsgRpcManager()


class BridgeHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        sys.stderr.write(f"[{ts}] {args[0]}\n")

    def _send_json(self, status: int, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _check_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and auth[7:].strip() == BRIDGE_TOKEN

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/health":
            self._send_json(200, {
                "status": "ok",
                "imsg_alive": rpc_manager.is_alive,
                "allowed_contact": ALLOWED_CONTACT,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            return

        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized"})
            return

        if path == "/notifications":
            notifications = rpc_manager.drain_notifications()
            self._send_json(200, {"notifications": notifications})
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")

        if not self._check_auth():
            self._send_json(401, {"error": "Unauthorized"})
            return

        try:
            body = self._read_body()
        except json.JSONDecodeError as e:
            self._send_json(400, {"error": f"Invalid JSON: {e}"})
            return

        if path == "/rpc":
            if not rpc_manager.is_alive:
                self._send_json(503, {"error": "imsg rpc is not running"})
                return
            result = rpc_manager.send_request(body)
            self._send_json(200, result)
            return

        self._send_json(404, {"error": "Not found"})


# ── Main ────────────────────────────────────────────────────────────────


def main():
    rpc_manager.start()

    server = http.server.HTTPServer((BRIDGE_HOST, BRIDGE_PORT), BridgeHandler)
    log(f"iMessage Bridge listening on {BRIDGE_HOST}:{BRIDGE_PORT}")
    log(f"Allowed contact: {ALLOWED_CONTACT}")

    def shutdown(signum=None, frame=None):
        log("Shutting down...")
        rpc_manager.stop()
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
