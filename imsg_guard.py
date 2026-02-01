#!/usr/bin/env python3
"""
imsg-guard — Security wrapper for imsg rpc (stdio mode).

Sits between a client (e.g. OpenClaw via SSH) and `imsg rpc` on stdio,
enforcing contact-based filtering. Only contacts defined in the contacts
file can send or receive messages.

Real phone numbers / emails stay local. If using the HTTP bridge mode
(imessage_bridge.py), remote clients only see aliases.

Usage:
    IMSG_CONTACTS_FILE="contacts.json" python3 imsg_guard.py rpc
    IMSG_CONTACTS='{"noah":"+15551234567"}' python3 imsg_guard.py rpc

Environment variables:
    IMSG_CONTACTS_FILE    Path to contacts JSON file (required unless IMSG_CONTACTS set)
    IMSG_CONTACTS         Inline JSON contacts map (alternative to file)
    IMSG_PATH             Path to imsg binary (default: /opt/homebrew/bin/imsg)

Contacts file format:
    { "alias": "+15551234567", "alias2": "user@icloud.com" }

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

IMSG_PATH = os.environ.get("IMSG_PATH", "/opt/homebrew/bin/imsg")

# ── Contacts ────────────────────────────────────────────────────────────

CONTACTS = {}           # alias -> real handle
HANDLE_TO_ALIAS = {}    # normalized handle -> alias
KNOWN_HANDLES = set()   # normalized handles for quick lookup


def normalize_handle(handle: str) -> str:
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
    global CONTACTS, HANDLE_TO_ALIAS, KNOWN_HANDLES

    raw = None
    contacts_file = os.environ.get("IMSG_CONTACTS_FILE", "")
    contacts_inline = os.environ.get("IMSG_CONTACTS", "")

    if contacts_file:
        try:
            with open(contacts_file) as f:
                raw = json.load(f)
        except FileNotFoundError:
            log(f"ERROR: Contacts file not found: {contacts_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            log(f"ERROR: Invalid JSON in contacts file: {e}")
            sys.exit(1)
    elif contacts_inline:
        try:
            raw = json.loads(contacts_inline)
        except json.JSONDecodeError as e:
            log(f"ERROR: Invalid IMSG_CONTACTS JSON: {e}")
            sys.exit(1)

    if not raw or not isinstance(raw, dict):
        log("ERROR: No contacts configured.")
        log("Set IMSG_CONTACTS_FILE or IMSG_CONTACTS env var")
        sys.exit(1)

    CONTACTS = {}
    HANDLE_TO_ALIAS = {}
    for alias, handle in raw.items():
        alias = alias.strip().lower()
        handle = handle.strip()
        if alias and handle:
            CONTACTS[alias] = handle
            norm = normalize_handle(handle)
            HANDLE_TO_ALIAS[norm] = alias
            KNOWN_HANDLES.add(norm)

    if not CONTACTS:
        log("ERROR: Contacts file is empty")
        sys.exit(1)

    log(f"Loaded {len(CONTACTS)} contact(s): {', '.join(CONTACTS.keys())}")


def is_known(handle: str) -> bool:
    return normalize_handle(handle) in KNOWN_HANDLES


# ── Helpers ─────────────────────────────────────────────────────────────


def log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[imsg-guard {ts}] {msg}", file=sys.stderr, flush=True)


def is_allowed_send(params: dict) -> bool:
    to = params.get("to", "")
    if to and is_known(to):
        return True
    # Also accept aliases directly
    if to and to.strip().lower() in CONTACTS:
        return True
    if params.get("chat_id") or params.get("chat_guid") or params.get("chat_identifier"):
        log("BLOCKED send: chat_id/chat_guid targets not allowed")
        return False
    if to:
        log(f"BLOCKED send to {to}: not in contacts")
    else:
        log("BLOCKED send: no 'to' field")
    return False


def is_allowed_notification(params: dict) -> bool:
    msg = params.get("message", params)
    if isinstance(msg, dict) and msg.get("is_from_me"):
        return False
    for obj in [msg, params] if isinstance(msg, dict) else [params]:
        for key in ("sender", "handle", "from", "address"):
            val = obj.get(key, "") if isinstance(obj, dict) else ""
            if isinstance(val, str) and val.strip() and is_known(val.strip()):
                return True
    # Try extracting sender for logging
    sender = ""
    for key in ("sender", "handle", "from", "address"):
        val = (msg if isinstance(msg, dict) else params).get(key, "")
        if isinstance(val, str) and val.strip():
            sender = val.strip()
            break
    if sender:
        log(f"DROPPED notification from {sender}: not in contacts")
    return False


# ── JSON-RPC proxy ──────────────────────────────────────────────────────


def make_error_response(req_id, code: int, message: str) -> str:
    return json.dumps({
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": code, "message": message}
    })


def proxy_stdin_to_imsg(imsg_stdin):
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
                            "Blocked by imsg-guard: recipient not in contacts"
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

            if msg.get("id") is not None:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
                continue

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
    load_contacts()

    log(f"imsg path: {IMSG_PATH}")

    args = [IMSG_PATH, "rpc"]
    argv = sys.argv[1:]
    if "--db" in argv:
        idx = argv.index("--db")
        if idx + 1 < len(argv):
            args.extend(["--db", argv[idx + 1]])

    try:
        proc = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, text=True, bufsize=1
        )
    except FileNotFoundError:
        log(f"ERROR: imsg not found at {IMSG_PATH}")
        sys.exit(1)

    log(f"imsg rpc started (pid {proc.pid})")

    stdin_thread = threading.Thread(target=proxy_stdin_to_imsg, args=(proc.stdin,), daemon=True)
    stdout_thread = threading.Thread(target=proxy_imsg_to_stdout, args=(proc.stdout,), daemon=True)
    stdin_thread.start()
    stdout_thread.start()

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

    proc.wait()
    code = proc.returncode
    if code != 0:
        log(f"imsg rpc exited with code {code}")
    sys.exit(code)


if __name__ == "__main__":
    main()
