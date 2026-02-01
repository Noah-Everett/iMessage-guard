# iMessage Guard

A security layer for [`imsg`](https://github.com/steipete/imsg) that restricts iMessage access to a single allowed contact. Designed for AI assistants (like [OpenClaw](https://github.com/openclaw/openclaw)) where you want your bot to message **only you** — even if the underlying `imsg` CLI has full access to Messages.app.

## Modes

iMessage Guard supports two deployment modes:

| Mode | Use case | Transport | Files |
|------|----------|-----------|-------|
| **HTTP Bridge** | OpenClaw on a different machine (VM, server) — no SSH needed | HTTP over network | `imessage_bridge.py` + `imsg_http_proxy.py` |
| **Stdio Guard** | OpenClaw on the same machine or connected via SSH | Stdio (JSON-RPC) | `imsg_guard.py` |

## Requirements

- macOS with Messages signed in (on the machine running `imsg`)
- Python 3.6+ (stdlib only — no `pip install`)
- [`imsg`](https://github.com/steipete/imsg): `brew install steipete/tap/imsg`

## HTTP Bridge Mode (recommended for remote setups)

Best when OpenClaw runs on a different machine than Messages (e.g., a VM connected via Tailscale).

```
┌─────────────────────────────────┐         HTTP         ┌──────────────────────────────────┐
│ OpenClaw machine (VM/server)    │◄────────────────────►│ Mac with Messages                │
│                                 │    (Tailscale etc.)  │                                  │
│ imsg_http_proxy.py (stdio)      │                      │ imessage_bridge.py (HTTP server)  │
│   └─ called by OpenClaw as      │                      │   └─ manages imsg rpc subprocess  │
│      channels.imessage.cliPath  │                      │   └─ filters by allowed contact   │
└─────────────────────────────────┘                      └──────────────────────────────────┘
```

### Setup

**On the Mac with Messages:**

```bash
# Install imsg
brew install steipete/tap/imsg

# Clone this repo
git clone https://github.com/Noah-Everett/iMessage-guard.git ~/iMessage-guard

# Start the bridge
export IMSG_ALLOWED_CONTACT="+15551234567"   # your phone or Apple ID
export IMSG_BRIDGE_TOKEN="your-secret-token" # pick a strong token
python3 ~/iMessage-guard/imessage_bridge.py
```

Grant macOS permissions on first run:
- **Full Disk Access**: System Settings → Privacy & Security → Full Disk Access → Terminal
- **Automation**: Approve when prompted (Messages.app control)

**On the OpenClaw machine:**

```bash
# Clone this repo
git clone https://github.com/Noah-Everett/iMessage-guard.git ~/iMessage-guard

# Create a wrapper script
cat > ~/.openclaw/scripts/imsg-bridge << 'EOF'
#!/usr/bin/env bash
export IMSG_BRIDGE_URL="http://100.x.y.z:8788"      # Mac's Tailscale IP
export IMSG_BRIDGE_TOKEN="your-secret-token"          # same token as bridge
exec python3 ~/iMessage-guard/imsg_http_proxy.py "$@"
EOF
chmod +x ~/.openclaw/scripts/imsg-bridge
```

**Configure OpenClaw:**

```json5
{
  channels: {
    imessage: {
      enabled: true,
      cliPath: "~/.openclaw/scripts/imsg-bridge",
      dmPolicy: "allowlist",
      allowFrom: ["+15551234567"],
      groupPolicy: "disabled"
    }
  }
}
```

### Bridge environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMSG_ALLOWED_CONTACT` | **Yes** | — | Phone number or Apple ID email |
| `IMSG_BRIDGE_TOKEN` | **Yes** | — | Bearer token for authentication |
| `IMSG_BRIDGE_HOST` | No | `0.0.0.0` | Bind address |
| `IMSG_BRIDGE_PORT` | No | `8788` | Listen port |
| `IMSG_PATH` | No | `/opt/homebrew/bin/imsg` | Path to imsg binary |
| `IMSG_DB_PATH` | No | — | Custom chat.db path |

### Proxy environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMSG_BRIDGE_URL` | **Yes** | — | Bridge URL (e.g., `http://100.x.y.z:8788`) |
| `IMSG_BRIDGE_TOKEN` | **Yes** | — | Bearer token (must match bridge) |
| `IMSG_POLL_MS` | No | `500` | Notification poll interval (ms) |

### Bridge API

#### `GET /health`
No auth required. Returns bridge status.

#### `POST /rpc`
Forward a JSON-RPC request to imsg. Returns the JSON-RPC response.

Send requests are validated — only messages to the allowed contact are forwarded.

#### `GET /notifications`
Returns and clears buffered inbound message notifications. Only notifications from the allowed contact are included.

```json
{
  "notifications": [
    "{\"jsonrpc\":\"2.0\",\"method\":\"message\",\"params\":{...}}"
  ]
}
```

---

## Stdio Guard Mode (for SSH or local setups)

Best when OpenClaw can reach `imsg` directly (same machine or via SSH).

```
OpenClaw → imsg_guard.py → imsg rpc → Messages.app
```

### Setup

```bash
export IMSG_ALLOWED_CONTACT="+15551234567"
python3 imsg_guard.py
```

### With OpenClaw (local)

```bash
cat > ~/.openclaw/scripts/imsg-guard << 'EOF'
#!/usr/bin/env bash
export IMSG_ALLOWED_CONTACT="+15551234567"
exec python3 /path/to/imsg_guard.py "$@"
EOF
chmod +x ~/.openclaw/scripts/imsg-guard
```

```json5
{
  channels: {
    imessage: {
      enabled: true,
      cliPath: "~/.openclaw/scripts/imsg-guard",
      dmPolicy: "allowlist",
      allowFrom: ["+15551234567"],
      groupPolicy: "disabled"
    }
  }
}
```

### With OpenClaw (SSH)

```bash
cat > ~/.openclaw/scripts/imsg-ssh << 'EOF'
#!/usr/bin/env bash
exec ssh -o BatchMode=yes -T user@mac-host \
  "IMSG_ALLOWED_CONTACT='+15551234567' python3 ~/iMessage-guard/imsg_guard.py" "$@"
EOF
chmod +x ~/.openclaw/scripts/imsg-ssh
```

### Stdio Guard environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMSG_ALLOWED_CONTACT` | **Yes** | — | Phone number or Apple ID email |
| `IMSG_PATH` | No | `/opt/homebrew/bin/imsg` | Path to imsg binary |

---

## How It Works

### Security filtering

Both modes enforce the same rules:

- **Outbound `send` requests**: Blocked unless `to` matches the allowed contact
- **`chat_id`/`chat_guid` targets**: Always blocked (can't verify recipient)
- **Inbound notifications**: Dropped unless sender matches the allowed contact
- **Self messages** (`is_from_me`): Dropped
- All blocked attempts logged to stderr

### Handle normalization

Phone numbers and emails are normalized before comparison:
- Service prefixes stripped: `imessage:`, `sms:`, `tel:`
- Phone numbers: non-digit chars removed, 10-digit US numbers get `+1` prefix
- Emails: case-insensitive

So `+1 (555) 123-4567`, `5551234567`, and `imessage:+15551234567` all match.

---

## Running as a LaunchAgent

To keep the bridge running across reboots on the Mac:

```bash
cat > ~/Library/LaunchAgents/com.imessage-guard.bridge.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.imessage-guard.bridge</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$HOME/iMessage-guard/imessage_bridge.py</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>IMSG_ALLOWED_CONTACT</key>
        <string>+15551234567</string>
        <key>IMSG_BRIDGE_TOKEN</key>
        <string>YOUR_TOKEN_HERE</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/imessage-bridge.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/imessage-bridge.log</string>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.imessage-guard.bridge.plist
```

---

## Security Summary

| Layer | What it does |
|-------|-------------|
| **iMessage Guard** | Blocks at the protocol level — unauthorized messages never reach imsg or the network |
| **OpenClaw `allowFrom`** | Second layer — OpenClaw ignores messages from anyone not in the list |
| **OpenClaw `groupPolicy: "disabled"`** | No group chat access |
| **Bearer token auth** (HTTP mode) | Prevents unauthorized access to the bridge |
| **Network** | Use Tailscale/VPN, not public internet |

## Troubleshooting

**Bridge: "imsg not found"** — Set `IMSG_PATH` or install: `brew install steipete/tap/imsg`

**Proxy: "Could not reach bridge"** — Check the bridge is running and the URL/port are correct. Verify Tailscale connectivity.

**No messages coming through** — Check bridge stderr for "DROPPED" lines. Run `imsg chats --limit 5` on the Mac to verify imsg works. Grant Full Disk Access + Automation permissions.

**Sends blocked** — Check bridge stderr for "BLOCKED" lines. Only direct `to` sends are allowed.

**Permission prompts** — On first run, open Terminal on the Mac and run `imsg chats --limit 1` to trigger macOS dialogs.

## License

MIT
