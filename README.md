# iMessage Guard

A security wrapper for [`imsg`](https://github.com/steipete/imsg) that restricts iMessage access to a single allowed contact. Designed for AI assistants (like [OpenClaw](https://github.com/openclaw/openclaw)) where you want your bot to message **only you** — even if the underlying `imsg` CLI has full access to Messages.app.

## What It Does

`imsg-guard` sits between your client and `imsg rpc` as a transparent stdio proxy:

```
Client (OpenClaw) → imsg-guard → imsg rpc → Messages.app
                  ← imsg-guard ← imsg rpc ←
```

**Outbound messages**: Blocked unless the recipient matches your allowed contact.  
**Inbound messages**: Dropped unless the sender matches your allowed contact.  
**Everything else**: Passed through transparently (health checks, etc.).

All blocked/dropped messages are logged to stderr.

## Why

`imsg` is powerful — it can send messages to anyone and read all your conversations. If you're giving an AI agent access to it, you probably want guardrails. This wrapper enforces a single-contact restriction at the protocol level, independent of any application-layer access controls.

Defense in depth: even if your AI framework's config gets misconfigured, the guard still blocks unauthorized messages.

## Requirements

- macOS with Messages signed in
- Python 3.6+
- [`imsg`](https://github.com/steipete/imsg) installed

## Installation

```bash
# Install imsg
brew install steipete/tap/imsg

# Clone this repo
git clone https://github.com/Noah-Everett/iMessage-guard.git
cd iMessage-guard
```

No Python dependencies needed — stdlib only.

## Quick Start

```bash
# Set your allowed contact
export IMSG_ALLOWED_CONTACT="+15551234567"  # or "user@icloud.com"

# Run it
python3 imsg_guard.py
```

The guard spawns `imsg rpc` and proxies all JSON-RPC traffic through the security filter.

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMSG_ALLOWED_CONTACT` | **Yes** | — | Phone number (`+15551234567`) or Apple ID email |
| `IMSG_PATH` | No | `/opt/homebrew/bin/imsg` | Path to `imsg` binary |

### Chat database path

To specify a custom Messages database path:

```bash
IMSG_ALLOWED_CONTACT="+15551234567" python3 imsg_guard.py --db /path/to/chat.db
```

## Usage with OpenClaw

iMessage Guard was built for [OpenClaw](https://github.com/openclaw/openclaw)'s `channels.imessage` integration. Here's how to set it up:

### Local setup (imsg on the same machine as OpenClaw)

1. Create a wrapper script (`~/.openclaw/scripts/imsg-guard`):

```bash
#!/usr/bin/env bash
set -euo pipefail
export IMSG_ALLOWED_CONTACT="+15551234567"
exec python3 /path/to/imsg_guard.py "$@"
```

```bash
chmod +x ~/.openclaw/scripts/imsg-guard
```

2. Configure OpenClaw:

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

### Remote setup (imsg on a different Mac, e.g. over SSH/Tailscale)

1. Copy `imsg_guard.py` to the remote Mac.

2. Create an SSH wrapper on the OpenClaw machine (`~/.openclaw/scripts/imsg-ssh`):

```bash
#!/usr/bin/env bash
set -euo pipefail
exec ssh -o BatchMode=yes -o ConnectTimeout=5 -T \
  user@mac-mini.tailnet.ts.net \
  "IMSG_ALLOWED_CONTACT='+15551234567' python3 ~/imsg_guard.py" "$@"
```

```bash
chmod +x ~/.openclaw/scripts/imsg-ssh
```

3. Configure OpenClaw:

```json5
{
  channels: {
    imessage: {
      enabled: true,
      cliPath: "~/.openclaw/scripts/imsg-ssh",
      dbPath: "/Users/you/Library/Messages/chat.db",
      remoteHost: "user@mac-mini.tailnet.ts.net",
      dmPolicy: "allowlist",
      allowFrom: ["+15551234567"],
      groupPolicy: "disabled"
    }
  }
}
```

### Security layers

With this setup you get three layers of protection:

| Layer | Enforcement |
|-------|-------------|
| **imsg-guard** | Blocks at the protocol level — unauthorized messages never reach `imsg` |
| **dmPolicy: "allowlist"** | OpenClaw ignores messages from anyone not in `allowFrom` |
| **groupPolicy: "disabled"** | No group chat access whatsoever |

## How It Works

imsg-guard proxies the [JSON-RPC 2.0](https://www.jsonrpc.org/specification) protocol that `imsg rpc` uses over stdio:

### Outbound (client → imsg)

1. Reads each JSON-RPC request from stdin
2. If the method is `send`:
   - Checks that the `to` parameter matches `IMSG_ALLOWED_CONTACT`
   - **Blocks** `chat_id`, `chat_guid`, and `chat_identifier` targets (can't verify the recipient)
   - Returns a JSON-RPC error response for blocked requests
3. All other methods pass through unchanged

### Inbound (imsg → client)

1. Reads each JSON-RPC message from imsg's stdout
2. **Responses** (messages with an `id` field) are always forwarded
3. **Notifications** with method `message`, `new_message`, or `message_received`:
   - Only forwarded if the sender matches `IMSG_ALLOWED_CONTACT`
   - Dropped silently otherwise (with a stderr log)
4. Other notifications (typing indicators, read receipts) pass through

### Handle normalization

Phone numbers and emails are normalized before comparison:

- Service prefixes stripped: `imessage:`, `sms:`, `tel:`
- Phone numbers: non-digit characters removed, 10-digit US numbers get `+1` prefix
- Emails: compared case-insensitively

So `+1 (555) 123-4567`, `5551234567`, `imessage:+15551234567`, and `tel:15551234567` all match.

## Troubleshooting

**"imsg not found"**: Set `IMSG_PATH` to the correct path, or install imsg: `brew install steipete/tap/imsg`

**"IMSG_ALLOWED_CONTACT is not set"**: Export the environment variable before running.

**Messages not coming through**: Check stderr logs for "DROPPED" lines. Verify the sender's handle matches your `IMSG_ALLOWED_CONTACT` after normalization.

**Sends being blocked**: Check stderr for "BLOCKED" lines. Only direct `to` sends are allowed — `chat_id`/`chat_guid` targets are blocked for security.

**Permission prompts on first run**: Run `imsg chats --limit 1` directly first to trigger macOS permission dialogs (Full Disk Access + Automation).

## License

MIT
