#!/usr/bin/env python3
"""
iMessage Bridge — HTTP bridge to imsg rpc.

Runs on the Mac where Messages is signed in. Manages an `imsg rpc` subprocess
and exposes its JSON-RPC interface over HTTP, with contact-based security filtering.

Real phone numbers / emails stay on this machine. Remote clients only see
aliases (e.g. "noah", "alice") defined in the contacts file.

Usage:
    IMSG_CONTACTS_FILE="contacts.json" IMSG_BRIDGE_TOKEN="secret" python3 imessage_bridge.py

Environment variables:
    IMSG_CONTACTS_FILE    Path to contacts JSON file (required unless IMSG_CONTACTS set)
    IMSG_CONTACTS         Inline JSON contacts map (alternative to file)
    IMSG_BRIDGE_TOKEN     Bearer token for HTTP auth (required)
    IMSG_BRIDGE_HOST      Bind address (default: 0.0.0.0)
    IMSG_BRIDGE_PORT      Listen port (default: 8788)
    IMSG_PATH             Path to imsg binary (default: /opt/homebrew/bin/imsg)
    IMSG_DB_PATH          Path to chat.db (optional, passed to imsg)

Contacts file format (JSON):
    {
      "noah": "+15551234567",
      "alice": "alice@icloud.com"
    }

Endpoints:
    GET  /health          — Health check (no auth)
    POST /rpc             — Forward a JSON-RPC request to imsg, return response
    GET  /notifications   — Return buffered inbound notifications, clear buffer
    GET  /contacts        — List available contact aliases (no real handles exposed)
"""

import http.server
import json
import os
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Config ──────────────────────────────────────────────────────────────

BRIDGE_TOKEN = os.environ.get("IMSG_BRIDGE_TOKEN", "")
BRIDGE_HOST = os.environ.get("IMSG_BRIDGE_HOST", "0.0.0.0")
BRIDGE_PORT = int(os.environ.get("IMSG_BRIDGE_PORT", "8788"))
IMSG_PATH = os.environ.get("IMSG_PATH", "/opt/homebrew/bin/imsg")
IMSG_DB_PATH = os.environ.get("IMSG_DB_PATH", "")

# Max notifications to buffer before dropping oldest
NOTIFICATION_BUFFER_MAX = 500
# Timeout waiting for an RPC response (seconds)
RPC_TIMEOUT = 15

if not BRIDGE_TOKEN:
    print("ERROR: IMSG_BRIDGE_TOKEN is required", file=sys.stderr)
    sys.exit(1)

# ── Contacts ────────────────────────────────────────────────────────────

# alias -> real handle (phone/email)
CONTACTS = {}
# real handle (normalized) -> alias (reverse lookup)
HANDLE_TO_ALIAS = {}


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


def load_contacts():
    """Load contacts from file or env var."""
    global CONTACTS, HANDLE_TO_ALIAS

    raw = None
    contacts_file = os.environ.get("IMSG_CONTACTS_FILE", "")
    contacts_inline = os.environ.get("IMSG_CONTACTS", "")

    if contacts_file:
        try:
            with open(contacts_file) as f:
                raw = json.load(f)
        except FileNotFoundError:
            print(f"ERROR: Contacts file not found: {contacts_file}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in contacts file: {e}", file=sys.stderr)
            sys.exit(1)
    elif contacts_inline:
        try:
            raw = json.loads(contacts_inline)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid IMSG_CONTACTS JSON: {e}", file=sys.stderr)
            sys.exit(1)

    if not raw or not isinstance(raw, dict):
        print("ERROR: No contacts configured.", file=sys.stderr)
        print("Set IMSG_CONTACTS_FILE=/path/to/contacts.json or IMSG_CONTACTS='{...}'",
              file=sys.stderr)
        sys.exit(1)

    CONTACTS = {}
    HANDLE_TO_ALIAS = {}
    for alias, handle in raw.items():
        alias = alias.strip().lower()
        handle = handle.strip()
        if not alias or not handle:
            continue
        CONTACTS[alias] = handle
        HANDLE_TO_ALIAS[normalize_handle(handle)] = alias

    if not CONTACTS:
        print("ERROR: Contacts file is empty", file=sys.stderr)
        sys.exit(1)

    log(f"Loaded {len(CONTACTS)} contact(s): {', '.join(CONTACTS.keys())}")


def resolve_alias(alias: str):
    """Resolve an alias to a real handle. Returns None if not found."""
    return CONTACTS.get(alias.strip().lower())


def resolve_handle(handle: str):
    """Resolve a real handle to an alias. Returns None if not in contacts."""
    return HANDLE_TO_ALIAS.get(normalize_handle(handle))


def is_known_handle(handle: str) -> bool:
    """Check if a handle belongs to any contact."""
    return normalize_handle(handle) in HANDLE_TO_ALIAS


# ── Security filtering ──────────────────────────────────────────────────


def filter_send_request(params: dict):
    """
    Validate and transform a send request.
    Resolves alias → real handle. Returns (allowed, modified_params).
    """
    to = params.get("to", "").strip()

    # Block indirect targets
    if params.get("chat_id") or params.get("chat_guid") or params.get("chat_identifier"):
        log("BLOCKED send: chat_id/chat_guid/chat_identifier targets not allowed")
        return False, params

    if not to:
        log("BLOCKED send: no 'to' field")
        return False, params

    # Try alias resolution first
    real_handle = resolve_alias(to)
    if real_handle:
        modified = dict(params)
        modified["to"] = real_handle
        return True, modified

    # Try direct handle (might be a real number/email that's in contacts)
    if is_known_handle(to):
        return True, params

    log(f"BLOCKED send to '{to}': not a known contact alias or handle")
    return False, params


def rewrite_notification(params: dict):
    """
    Filter and rewrite an inbound notification.
    Replaces real handles with aliases. Returns None if sender not in contacts.
    """
    msg = params.get("message", {})
    if not isinstance(msg, dict):
        return None

    # Skip self messages — check multiple locations and formats
    for obj in [msg, params]:
        from_me = obj.get("is_from_me")
        if from_me is True or from_me == 1 or from_me == "true" or from_me == "1":
            return None

    # Find sender
    sender = ""
    for key in ("sender", "handle", "from", "address"):
        val = msg.get(key, "")
        if isinstance(val, str) and val.strip():
            sender = val.strip()
            break

    if not sender:
        # Check top-level params too
        for key in ("sender", "handle", "from", "address"):
            val = params.get(key, "")
            if isinstance(val, str) and val.strip():
                sender = val.strip()
                break

    if not sender:
        return None

    # Resolve to alias
    alias = resolve_handle(sender)
    if not alias:
        log(f"DROPPED notification from {sender}: not in contacts")
        return None

    # Rewrite: replace real handle with alias in the notification
    rewritten = json.loads(json.dumps(params))  # deep copy

    # Rewrite message-level sender fields
    rewritten_msg = rewritten.get("message", {})
    if isinstance(rewritten_msg, dict):
        for key in ("sender", "handle", "from", "address"):
            if key in rewritten_msg:
                rewritten_msg[key] = alias

    # Rewrite top-level sender fields
    for key in ("sender", "handle", "from", "address"):
        if key in rewritten:
            rewritten[key] = alias

    return rewritten


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
        self.pending = {}
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

        # Auto-subscribe to watch for incoming messages
        self._auto_subscribe()

    def _auto_subscribe(self):
        """Subscribe to message watch on startup so inbound messages flow immediately."""
        try:
            result = self.send_request({
                "jsonrpc": "2.0",
                "id": -1,
                "method": "watch.subscribe",
                "params": {"attachments": False}
            }, timeout=10)
            sub_id = (result or {}).get("result", {}).get("subscription")
            if sub_id is not None:
                log(f"Auto-subscribed to watch (subscription={sub_id})")
            else:
                log(f"Watch subscribe response: {result}")
        except Exception as e:
            log(f"Warning: auto-subscribe failed: {e}")

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
        """Read from imsg stdout, route responses and buffer notifications."""
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

                # Notification — filter and rewrite
                method = msg.get("method", "")
                params = msg.get("params", {})

                if method in ("message", "new_message", "message_received"):
                    rewritten = rewrite_notification(params)
                    if rewritten is None:
                        continue
                    # Store the rewritten notification
                    rewritten_msg = dict(msg)
                    rewritten_msg["params"] = rewritten
                    with self.notifications_lock:
                        self.notifications.append(json.dumps(rewritten_msg))
                        if len(self.notifications) > NOTIFICATION_BUFFER_MAX:
                            self.notifications = self.notifications[-NOTIFICATION_BUFFER_MAX:]
                else:
                    # Non-message notifications pass through
                    with self.notifications_lock:
                        self.notifications.append(json.dumps(msg))
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
        method = request.get("method", "")
        params = request.get("params", {})

        # No id = notification from client, just forward
        if req_id is None:
            with self.stdin_lock:
                self.proc.stdin.write(json.dumps(request) + "\n")
                self.proc.stdin.flush()
            return {}

        # Security: validate and transform send requests
        if method == "send":
            allowed, modified_params = filter_send_request(params)
            if not allowed:
                return {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32001,
                               "message": "Blocked by iMessage bridge: recipient not in contacts"}
                }
            # Use modified params (alias resolved to real handle)
            request = dict(request)
            request["params"] = modified_params

        # Register pending response
        key = str(req_id)
        event = threading.Event()
        entry = {"event": event, "result": None}

        with self.pending_lock:
            self.pending[key] = entry

        try:
            with self.stdin_lock:
                self.proc.stdin.write(json.dumps(request) + "\n")
                self.proc.stdin.flush()

            if event.wait(timeout=timeout):
                return entry["result"]
            else:
                return {
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32000, "message": f"Timeout ({timeout}s)"}
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
                "contacts": list(CONTACTS.keys()),
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

        if path == "/contacts":
            self._send_json(200, {
                "contacts": list(CONTACTS.keys())
            })
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
    load_contacts()
    rpc_manager.start()

    server = http.server.HTTPServer((BRIDGE_HOST, BRIDGE_PORT), BridgeHandler)
    log(f"iMessage Bridge listening on {BRIDGE_HOST}:{BRIDGE_PORT}")

    def shutdown(signum=None, frame=None):
        log("Shutting down...")
        rpc_manager.stop()
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
