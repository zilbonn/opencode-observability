# ⚠️ THIS WAS NOT MADE BY ME THIS IS THE OPENCODE VERSION OF THIS REPO https://github.com/disler/claude-code-hooks-multi-agent-observability
 
# OpenCode Multi-Agent Observability

A plugin and dashboard for observing OpenCode agent activities in real-time. Compatible with the [claude-code-hooks-multi-agent-observability](https://github.com/disler/claude-code-hooks-multi-agent-observability) system.

## Features

- Real-time event tracking for OpenCode agents
- Web dashboard with filtering and search
- Compatible with both OpenCode and Claude Code
- WebSocket live updates
- Session tracking across multiple agents

## Quick Start

### 1. Install Dependencies

```bash
# Server
cd apps/server && bun install

# Client
cd apps/client && bun install
```

### 2. Start the System

```bash
./scripts/start-system.sh
```

Or manually:

```bash
# Terminal 1: Server
cd apps/server && bun run src/index.ts

# Terminal 2: Client
cd apps/client && bun run dev
```

### 3. Install OpenCode Plugin

```bash
./scripts/setup-opencode.sh
```

### 4. Open Dashboard

Navigate to http://localhost:5173

## Configuration

### Environment Variables

Add to `/opt/env.sh` or your shell profile:

```bash
export OBSERVABILITY_SERVER_URL="http://localhost:4000/events"
export OBSERVABILITY_SOURCE_APP="wardenn"
export OPENCODE_CONFIG="/opt/opencode.jsonc"
```

### OpenCode Config

Create `/opt/opencode.jsonc`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-opus-4-5",
  "permission": {
    "*": "allow"
  }
}
```

## Event Types

| Event | Description |
|-------|-------------|
| PreToolUse | Before tool execution |
| PostToolUse | After tool execution |
| SessionStart | New session started |
| Stop | Session ended |
| PreCompact | Context compaction |
| UserPromptSubmit | User message sent |
| Notification | Permission/notification events |

## Architecture

```
OpenCode Agent → Plugin → HTTP POST → Bun Server → SQLite → WebSocket → Vue Dashboard
```

## Usage with Wardenn

```bash
source /opt/env.sh && opencode run "Your prompt here"
```

Events will appear in the dashboard in real-time.

## License

MIT
