#!/usr/bin/env python3
"""
imsg-guard — Security wrapper for imsg rpc.

Sits between a client (e.g. OpenClaw) and `imsg rpc` on stdio, enforcing that
only a configurable set of allowed contacts can send or receive messages.

Usage:
    IMSG_ALLOWED_CONTACT="+15551234567" python3 imsg_guard.py
    IMSG_ALLOWED_CONTACT="+15551234567" IMSG_PATH=/opt/homebrew/bin/imsg python3 imsg_guard.py
    IMSG_ALLOWED_CONTACT="user@icloud.com" python3 imsg_guard.py --db /path/to/chat.db

Protocol: JSON-RPC 2.0 over newline-delimited stdio (same as `imsg rpc`).

Security guarantees:
    - Outbound `send` requests are BLOCKED unless the recipient matches ALLOWED_CONTACT.
    - Inbound message notifications are DROPPED unless the sender matches ALLOWED_CONTACT.
    - chat_id / chat_guid / chat_identifier targets are blocked (can't verify recipient).
    - All blocked attempts are logged to stderr.
    - Non-send RPC methods pass through unchanged.

Environment variables:
    IMSG_ALLOWED_CONTACT  Phone number (+15551234567) or Apple ID email (required)
    IMSG_PATH             Path to imsg binary (default: /opt/homebrew/bin/imsg)

See README.md for full documentation.
"""

import json
import os
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone

# ── Config ──────────────────────────────────────────────────────────────

ALLOWED_CONTACT = os.environ.get("IMSG_ALLOWED_CONTACT", "")
IMSG_PATH = os.environ.get("IMSG_PATH", "/opt/homebrew/bin/imsg")

# ── Helpers ─────────────────────────────────────────────────────────────


def log(msg: str):
    """Log to stderr (doesn't interfere with stdio JSON-RPC)."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[imsg-guard {ts}] {msg}", file=sys.stderr, flush=True)


def normalize_handle(handle: str) -> str:
    """
    Normalize a phone number or email for comparison.

    Handles:
        - Service prefixes: imessage:, sms:, tel:
        - US phone number variants: +15551234567, 5551234567, (555) 123-4567
        - Email addresses (case-insensitive)
    """
    h = handle.strip().lower()

    # Strip service prefixes
    for prefix in ("imessage:", "sms:", "tel:"):
        if h.startswith(prefix):
            h = h[len(prefix):]

    h = h.strip()

    # Phone number: extract digits and normalize
    if h.startswith("+") or (h and h[0].isdigit()) or h.startswith("("):
        digits = "".join(c for c in h if c.isdigit())
        # Normalize US numbers: 10 digits → +1 prefix
        if len(digits) == 10:
            digits = "1" + digits
        if digits:
            return "+" + digits

    # Email or other handle
    return h


def is_allowed(handle: str) -> bool:
    """Check if a handle matches the allowed contact."""
    if not handle or not ALLOWED_CONTACT:
        return False
    return normalize_handle(handle) == normalize_handle(ALLOWED_CONTACT)


def is_allowed_send(params: dict) -> bool:
    """
    Check if a send request targets the allowed contact.

    Only direct `to` sends are allowed. Chat ID/GUID targets are blocked
    because we can't verify the recipient without querying imsg.
    """
    to = params.get("to", "")
    if to and is_allowed(to):
        return True

    # Block indirect targets — can't verify recipient
    if params.get("chat_id") or params.get("chat_guid") or params.get("chat_identifier"):
        log("BLOCKED send: chat_id/chat_guid/chat_identifier targets not allowed "
            "(use direct 'to' handle for security)")
        return False

    if to:
        log(f"BLOCKED send to {to}: not in allowlist")
    else:
        log("BLOCKED send: no 'to' field provided")
    return False


def is_allowed_notification(params: dict) -> bool:
    """
    Check if an incoming message notification is from the allowed contact.

    Checks multiple field locations since the notification format may vary
    across imsg versions.
    """
    # Check top-level sender fields
    sender = _extract_sender(params)
    if sender and is_allowed(sender):
        return True

    # Check nested message object
    msg = params.get("message", {})
    if isinstance(msg, dict):
        sender = _extract_sender(msg)
        if sender and is_allowed(sender):
            return True

    if sender:
        log(f"DROPPED notification from {sender}: not in allowlist")
    return False


def _extract_sender(obj: dict) -> str:
    """Extract sender handle from a dict, checking common field names."""
    for key in ("sender", "handle", "from", "address"):
        val = obj.get(key, "")
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


# ── JSON-RPC proxy ──────────────────────────────────────────────────────


def make_error_response(req_id, code: int, message: str) -> str:
    """Create a JSON-RPC 2.0 error response."""
    return json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message}
    })


def proxy_stdin_to_imsg(imsg_stdin):
    """
    Read JSON-RPC requests from stdin, validate send targets, forward to imsg.

    Non-send methods are forwarded without modification.
    Send requests to disallowed contacts receive an error response directly
    without ever reaching imsg.
    """
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                imsg_stdin.write(line + "\n")
                imsg_stdin.flush()
                continue

            method = msg.get("method", "")
            params = msg.get("params", {})
            req_id = msg.get("id")

            if method == "send":
                if not is_allowed_send(params):
                    if req_id is not None:
                        err = make_error_response(
                            req_id, -32001,
                            "Blocked by imsg-guard: recipient not in allowlist"
                        )
                        sys.stdout.write(err + "\n")
                        sys.stdout.flush()
                    continue

            imsg_stdin.write(line + "\n")
            imsg_stdin.flush()

    except (BrokenPipeError, IOError):
        pass
    finally:
        try:
            imsg_stdin.close()
        except Exception:
            pass


def proxy_imsg_to_stdout(imsg_stdout):
    """
    Read JSON-RPC from imsg stdout, filter notifications, forward to stdout.

    Responses (with id) are always forwarded.
    Message notifications are only forwarded if the sender is allowed.
    Other notifications (typing, read receipts, etc.) pass through.
    """
    try:
        for line in imsg_stdout:
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
                continue

            # Responses to requests — always forward
            if msg.get("id") is not None:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
                continue

            # Notifications — filter message events
            method = msg.get("method", "")
            params = msg.get("params", {})

            if method in ("message", "new_message", "message_received"):
                if not is_allowed_notification(params):
                    continue

            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    except (BrokenPipeError, IOError):
        pass


# ── Main ────────────────────────────────────────────────────────────────


def main():
    if not ALLOWED_CONTACT:
        log("ERROR: IMSG_ALLOWED_CONTACT is not set.")
        log("Set it as an environment variable: export IMSG_ALLOWED_CONTACT='+15551234567'")
        sys.exit(1)

    log(f"Starting — allowed contact: {ALLOWED_CONTACT}")
    log(f"imsg path: {IMSG_PATH}")

    # Build imsg rpc args
    args = [IMSG_PATH, "rpc"]

    # Pass through --db flag
    argv = sys.argv[1:]
    if "--db" in argv:
        idx = argv.index("--db")
        if idx + 1 < len(argv):
            args.extend(["--db", argv[idx + 1]])

    # Spawn imsg rpc
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1  # Line buffered
        )
    except FileNotFoundError:
        log(f"ERROR: imsg not found at {IMSG_PATH}")
        log("Install with: brew install steipete/tap/imsg")
        sys.exit(1)

    log(f"imsg rpc started (pid {proc.pid})")

    # Start proxy threads
    stdin_thread = threading.Thread(
        target=proxy_stdin_to_imsg,
        args=(proc.stdin,),
        daemon=True
    )
    stdout_thread = threading.Thread(
        target=proxy_imsg_to_stdout,
        args=(proc.stdout,),
        daemon=True
    )
    stdin_thread.start()
    stdout_thread.start()

    # Graceful shutdown
    def shutdown(signum=None, frame=None):
        log("Shutting down...")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Wait for imsg to exit
    proc.wait()
    code = proc.returncode
    if code != 0:
        log(f"imsg rpc exited with code {code}")
    sys.exit(code)


if __name__ == "__main__":
    main()
