#!/usr/bin/env python3
"""
imsg HTTP Proxy — Local stdio proxy that talks to imessage_bridge over HTTP.

Replaces `imsg rpc` as OpenClaw's cliPath. Speaks JSON-RPC over stdio
(what OpenClaw expects) but forwards everything to the remote iMessage bridge
via HTTP.

Usage:
    IMSG_BRIDGE_URL="http://100.77.56.119:8788" \
    IMSG_BRIDGE_TOKEN="secret" \
    python3 imsg_http_proxy.py rpc [--db ignored]

OpenClaw config:
    channels.imessage.cliPath = "/path/to/imsg_http_proxy.py"

Environment variables:
    IMSG_BRIDGE_URL    Base URL of the iMessage bridge (required)
    IMSG_BRIDGE_TOKEN  Bearer token for bridge auth (required)
    IMSG_POLL_MS       Notification poll interval in ms (default: 500)
"""

import json
import os
import signal
import sys
import threading
import time
import urllib.request
import urllib.error

# ── Config ──────────────────────────────────────────────────────────────

BRIDGE_URL = os.environ.get("IMSG_BRIDGE_URL", "").rstrip("/")
BRIDGE_TOKEN = os.environ.get("IMSG_BRIDGE_TOKEN", "")
POLL_INTERVAL = int(os.environ.get("IMSG_POLL_MS", "500")) / 1000.0

if not BRIDGE_URL:
    print("ERROR: IMSG_BRIDGE_URL is required", file=sys.stderr)
    sys.exit(1)
if not BRIDGE_TOKEN:
    print("ERROR: IMSG_BRIDGE_TOKEN is required", file=sys.stderr)
    sys.exit(1)


# ── Helpers ─────────────────────────────────────────────────────────────

stdout_lock = threading.Lock()


def log(msg: str):
    print(f"[imsg-proxy] {msg}", file=sys.stderr, flush=True)


def write_stdout(line: str):
    """Thread-safe write to stdout."""
    with stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def http_post(path: str, data: dict, timeout: float = 20) -> dict:
    """POST JSON to the bridge and return parsed response."""
    url = f"{BRIDGE_URL}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {BRIDGE_TOKEN}",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
        except Exception:
            err_body = {"error": f"HTTP {e.code}"}
        return err_body
    except Exception as e:
        return {"error": str(e)}


def http_get(path: str, timeout: float = 10) -> dict:
    """GET from the bridge and return parsed response."""
    url = f"{BRIDGE_URL}{path}"
    req = urllib.request.Request(
        url, method="GET",
        headers={"Authorization": f"Bearer {BRIDGE_TOKEN}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
        except Exception:
            err_body = {"error": f"HTTP {e.code}"}
        return err_body
    except Exception as e:
        return {"error": str(e)}


# ── Notification poller ─────────────────────────────────────────────────

def poll_notifications(stop_event: threading.Event):
    """Poll the bridge for notifications and write them to stdout."""
    consecutive_errors = 0
    while not stop_event.is_set():
        try:
            result = http_get("/notifications", timeout=5)
            notifications = result.get("notifications", [])
            for n in notifications:
                # Each notification is a JSON string
                if isinstance(n, str):
                    write_stdout(n)
                else:
                    write_stdout(json.dumps(n))
            consecutive_errors = 0
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors <= 3:
                log(f"Poll error: {e}")
            # Back off on repeated errors
            if consecutive_errors > 5:
                time.sleep(min(consecutive_errors * POLL_INTERVAL, 10))

        stop_event.wait(POLL_INTERVAL)


# ── Stdin reader (JSON-RPC requests) ───────────────────────────────────

def process_stdin(stop_event: threading.Event):
    """Read JSON-RPC from stdin, forward to bridge, write responses to stdout."""
    try:
        for line in sys.stdin:
            if stop_event.is_set():
                break
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Forward to bridge
            result = http_post("/rpc", msg)

            # Write response to stdout (if it has content)
            if result:
                write_stdout(json.dumps(result))

    except (BrokenPipeError, IOError):
        pass
    finally:
        stop_event.set()


# ── Main ────────────────────────────────────────────────────────────────

def main():
    # Accept 'rpc' subcommand (for OpenClaw compatibility)
    # Also accept and ignore --db flag
    args = sys.argv[1:]
    if args and args[0] != "rpc":
        print(f"Usage: {sys.argv[0]} rpc [--db path]", file=sys.stderr)
        sys.exit(1)

    # Quick health check
    try:
        health = http_get("/health", timeout=5)
        if health.get("status") == "ok":
            log(f"Connected to bridge at {BRIDGE_URL}")
            log(f"imsg alive: {health.get('imsg_alive')}")
        else:
            log(f"WARNING: Bridge health check returned: {health}")
    except Exception as e:
        log(f"WARNING: Could not reach bridge at {BRIDGE_URL}: {e}")
        log("Continuing anyway — bridge may come up later")

    stop_event = threading.Event()

    # Start notification poller
    poller = threading.Thread(
        target=poll_notifications,
        args=(stop_event,),
        daemon=True
    )
    poller.start()

    # Handle shutdown
    def shutdown(signum=None, frame=None):
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Process stdin (blocks until EOF or error)
    process_stdin(stop_event)


if __name__ == "__main__":
    main()
