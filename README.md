# iMessage Guard

A security layer for [`imsg`](https://github.com/steipete/imsg) that restricts iMessage access to specific contacts. Real phone numbers and emails stay on the Mac — remote clients (like your AI assistant) only see aliases you define.

## How It Works

You create a `contacts.json` on the Mac with Messages:

```json
{
  "noah": "+15551234567",
  "alice": "alice@icloud.com"
}
```

Your AI assistant sees `noah` and `alice` — never the real numbers or emails. Messages to/from anyone not in the contacts file are blocked.

## Modes

| Mode | Use case | Transport | Files |
|------|----------|-----------|-------|
| **HTTP Bridge** | OpenClaw on a different machine — no SSH | HTTP over network | `imessage_bridge.py` + `imsg_http_proxy.py` |
| **Stdio Guard** | OpenClaw on same machine or via SSH | Stdio (JSON-RPC) | `imsg_guard.py` |

## Requirements

- macOS with Messages signed in (on the machine running `imsg`)
- Python 3.6+ (stdlib only — no `pip install`)
- [`imsg`](https://github.com/steipete/imsg): `brew install steipete/tap/imsg`

---

## HTTP Bridge Mode (recommended for remote setups)

Best when OpenClaw runs on a different machine than Messages.

```
┌─────────────────────────────────┐         HTTP         ┌──────────────────────────────────┐
│ OpenClaw machine (VM/server)    │◄────────────────────►│ Mac with Messages                │
│                                 │    (Tailscale etc.)  │                                  │
│ imsg_http_proxy.py              │                      │ imessage_bridge.py               │
│  └─ OpenClaw sees aliases only  │                      │  └─ contacts.json has real info   │
│  └─ never sees real numbers     │                      │  └─ manages imsg rpc              │
└─────────────────────────────────┘                      └──────────────────────────────────┘
```

### Setup

**On the Mac with Messages:**

```bash
# Install imsg
brew install steipete/tap/imsg

# Clone this repo
git clone https://github.com/Noah-Everett/iMessage-guard.git ~/iMessage-guard
cd ~/iMessage-guard

# Create your contacts file
cp contacts.example.json contacts.json
# Edit contacts.json with your actual contacts:
#   { "noah": "+15551234567" }

# Start the bridge
export IMSG_CONTACTS_FILE="$HOME/iMessage-guard/contacts.json"
export IMSG_BRIDGE_TOKEN="pick-a-strong-secret-token"
python3 imessage_bridge.py
```

**On the OpenClaw machine:**

```bash
git clone https://github.com/Noah-Everett/iMessage-guard.git ~/iMessage-guard

# Create a wrapper script
mkdir -p ~/.openclaw/scripts
cat > ~/.openclaw/scripts/imsg-bridge << 'EOF'
#!/usr/bin/env bash
export IMSG_BRIDGE_URL="http://100.x.y.z:8788"      # Mac's IP (Tailscale etc.)
export IMSG_BRIDGE_TOKEN="pick-a-strong-secret-token" # must match bridge
exec python3 ~/iMessage-guard/imsg_http_proxy.py "$@"
EOF
chmod +x ~/.openclaw/scripts/imsg-bridge
```

**Configure OpenClaw** (uses aliases, not real numbers):

```json5
{
  channels: {
    imessage: {
      enabled: true,
      cliPath: "~/.openclaw/scripts/imsg-bridge",
      dmPolicy: "allowlist",
      allowFrom: ["noah"],           // alias, not phone number
      groupPolicy: "disabled"
    }
  }
}
```

### Bridge environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMSG_CONTACTS_FILE` | Yes* | — | Path to contacts JSON file |
| `IMSG_CONTACTS` | Yes* | — | Inline JSON (alternative to file) |
| `IMSG_BRIDGE_TOKEN` | **Yes** | — | Bearer token for HTTP auth |
| `IMSG_BRIDGE_HOST` | No | `0.0.0.0` | Bind address |
| `IMSG_BRIDGE_PORT` | No | `8788` | Listen port |
| `IMSG_PATH` | No | `/opt/homebrew/bin/imsg` | Path to imsg |
| `IMSG_DB_PATH` | No | — | Custom chat.db path |

\* One of `IMSG_CONTACTS_FILE` or `IMSG_CONTACTS` is required.

### Proxy environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMSG_BRIDGE_URL` | **Yes** | — | Bridge URL (e.g., `http://100.x.y.z:8788`) |
| `IMSG_BRIDGE_TOKEN` | **Yes** | — | Must match bridge token |
| `IMSG_POLL_MS` | No | `500` | Poll interval in ms |

### Bridge API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | No | Status + contact alias list |
| `POST /rpc` | Yes | Forward JSON-RPC to imsg (aliases resolved to real handles) |
| `GET /notifications` | Yes | Buffered inbound messages (real handles replaced with aliases) |
| `GET /contacts` | Yes | List contact aliases |

---

## Stdio Guard Mode

For when OpenClaw runs on the same Mac or connects via SSH.

```bash
export IMSG_CONTACTS_FILE="contacts.json"
python3 imsg_guard.py rpc
```

### OpenClaw config (local)

```bash
cat > ~/.openclaw/scripts/imsg-guard << 'EOF'
#!/usr/bin/env bash
export IMSG_CONTACTS_FILE="$HOME/iMessage-guard/contacts.json"
exec python3 ~/iMessage-guard/imsg_guard.py "$@"
EOF
chmod +x ~/.openclaw/scripts/imsg-guard
```

### OpenClaw config (SSH)

```bash
cat > ~/.openclaw/scripts/imsg-ssh << 'EOF'
#!/usr/bin/env bash
exec ssh -o BatchMode=yes -T user@mac-host \
  "IMSG_CONTACTS_FILE=~/iMessage-guard/contacts.json python3 ~/iMessage-guard/imsg_guard.py" "$@"
EOF
```

---

## Contacts File

A simple JSON map of alias → handle:

```json
{
  "noah": "+15551234567",
  "alice": "alice@icloud.com",
  "bob": "+44207946000"
}
```

- **Aliases** are lowercase, user-defined names
- **Handles** are phone numbers (E.164) or Apple ID emails
- Only contacts in this file can send or receive messages
- The file lives on the Mac with Messages — never shared with remote clients
- Phone numbers are normalized for matching: `5551234567`, `+15551234567`, `(555) 123-4567` all work

To add/remove contacts, edit the file and restart the bridge.

---

## Security

| Layer | What it does |
|-------|-------------|
| **Contacts file** | Only listed contacts can send/receive — enforced at protocol level |
| **Alias mapping** | Real handles never leave the Mac; clients only see aliases |
| **chat_id blocking** | Indirect targets blocked (can't verify recipient) |
| **Bearer token** (HTTP mode) | Prevents unauthorized access to the bridge API |
| **OpenClaw `allowFrom`** | Additional layer — OpenClaw ignores messages from unlisted aliases |
| **Network** | Use Tailscale/VPN, not public internet |

---

## Running as a LaunchAgent

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
        <key>IMSG_CONTACTS_FILE</key>
        <string>$HOME/iMessage-guard/contacts.json</string>
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

## Troubleshooting

**"imsg not found"** — `brew install steipete/tap/imsg` or set `IMSG_PATH`

**"No contacts configured"** — Set `IMSG_CONTACTS_FILE` or `IMSG_CONTACTS`

**"Could not reach bridge"** — Check bridge is running, URL/port are correct, network (Tailscale) is up

**No messages coming through** — Check stderr for "DROPPED" lines. Verify the sender's handle matches what's in contacts.json (run `imsg chats --limit 5` to see handles).

**Sends blocked** — Check stderr for "BLOCKED" lines. Make sure the alias or handle is in contacts.json.

**macOS permissions** — Run `imsg chats --limit 1` in Terminal on the Mac to trigger Full Disk Access + Automation prompts.

## License

MIT
