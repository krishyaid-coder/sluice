# Sluice End-to-End User Guide

Professional guide for installing, configuring, and validating Sluice on your machine. Follow this document top to bottom for a complete first run.

**Version:** 0.3.0  
**PyPI package:** `sluice-taint`  
**CLI command:** `sluice`

---

## 1. What Sluice does

Sluice sits between an AI agent (Cursor, Claude Desktop, Cline, custom) and one or more MCP tool servers. It inspects every JSON-RPC message in both directions:

1. **Detectors** scan for secrets, PII, tool-poisoning patterns, and prompt-injection phrases.
2. **Policy** decides whether to block, redact, flag, or pass each hit.
3. **Session taint** remembers sensitive values that appeared in earlier tool responses and blocks reuse in later tool calls (`taint_leak`).

The headline scenario:

```
read_file  → response contains AKIAIOSFODNN7EXAMPLE   ✓ allowed (first sighting)
send_email → body contains same AKIAIOSFODNN7EXAMPLE  ✗ blocked (taint_leak)
```

---

## 2. Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | Required for `pip install` |
| macOS / Linux / WSL | Primary targets; Windows works via WSL |
| Node.js 18+ (optional) | Only if you use `npx` MCP servers (filesystem, etc.) |
| `curl` or `httpx` | For HTTP-mode testing |

For **Cursor / Claude Desktop** integration you need stdio mode (no Docker for the desktop client path).

---

## 3. Installation

### Option A — PyPI (recommended)

```bash
pip install sluice-taint
sluice version
```

Expected output: `sluice 0.3.0`

### Option B — From source

```bash
git clone https://github.com/krishyaid-coder/sluice
cd sluice
pip install -e ".[dev]"
pytest tests/ -v -m "not integration"
```

### Option C — Docker (HTTP mode only)

```bash
docker build -t sluice:local .
sluice init --path ./config.yaml   # on host, before mounting
docker run --rm -p 4444:4444 \
  -v "$PWD/config.yaml:/etc/sluice/config.yaml:ro" \
  -v sluice-audit:/var/lib/sluice \
  sluice:local serve --config /etc/sluice/config.yaml --host 0.0.0.0
```

Docker does **not** support stdio mode. Use pip for Claude Desktop / Cursor.

---

## 4. Five-minute validation (HTTP)

This proves install, policy, and blocking work without touching a desktop client.

### Step 1 — Scaffold config

```bash
mkdir -p ~/sluice-lab && cd ~/sluice-lab
sluice init
```

This writes `config.yaml` with a filesystem upstream preset and default policy.

### Step 2 — Start the gate

```bash
sluice serve
```

You should see:

```
Sluice listening on http://127.0.0.1:4444
Dashboard: http://127.0.0.1:4444/_sluice/
```

Leave this terminal open.

### Step 3 — Block a secret on outbound traffic

In a second terminal:

```bash
curl -s -X POST http://127.0.0.1:4444/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "write_file",
      "arguments": {"content": "AKIAIOSFODNN7EXAMPLE"}
    }
  }' | python3 -m json.tool
```

**Expected:** JSON-RPC `error` with a message about refusing the call (secrets detector + `block` policy).

### Step 4 — Run the bundled demo script

From the repo root (or after `git clone`):

```bash
bash scripts/demo.sh
```

Same behavior: blocked request, JSON-RPC error.

### Step 5 — Check audit log

```bash
sluice logs --since 1h
```

**Expected:** rows with `action` = `block` and `detectors` containing a secrets rule.

Open the dashboard at [http://127.0.0.1:4444/_sluice/](http://127.0.0.1:4444/_sluice/) to see the same events in a browser.

---

## 5. End-to-end taint leak test (the core feature)

This is the scenario you should run to validate session memory.

### Setup — mock upstream (no Node required)

Create `~/sluice-lab/mock_server.py`:

```python
#!/usr/bin/env python3
import json, sys
SECRET = "AKIAIOSFODNN7EXAMPLE"

def respond(req):
    m, i = req.get("method"), req.get("id")
    if m == "tools/call":
        tool = req.get("params", {}).get("name")
        if tool == "read_file":
            return {"jsonrpc": "2.0", "id": i,
                    "result": {"content": [{"type": "text", "text": SECRET}]}}
        if tool == "send_email":
            return {"jsonrpc": "2.0", "id": i,
                    "result": {"content": [{"type": "text", "text": "sent"}]}}
    return {"jsonrpc": "2.0", "id": i, "result": {"ok": True}}

for line in sys.stdin:
    if not line.strip(): continue
    req = json.loads(line)
    out = respond(req)
    if out: print(json.dumps(out), flush=True)
```

Create `~/sluice-lab/config.yaml`:

```yaml
version: 1

proxy:
  host: 127.0.0.1
  port: 4444

upstreams:
  - name: lab
    transport: stdio
    command: python3
    args: ["/Users/YOU/sluice-lab/mock_server.py"]

routing:
  default: lab

policy:
  rules:
    - detector: secrets.*
      action: flag          # allow first sighting, remember value
  default_action: pass

taint:
  enabled: true
  min_length: 12
  provenance: true

audit:
  sink: sqlite
  sqlite:
    path: ~/.sluice/audit.db

dashboard:
  enabled: true
```

Replace `/Users/YOU/` with your home path.

### Run

```bash
cd ~/sluice-lab
sluice serve --config config.yaml
```

### Turn 1 — read (plants taint)

```bash
curl -s -X POST http://127.0.0.1:4444/ \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: lab-session-1" \
  -d '{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}}
  }' | python3 -m json.tool
```

**Expected:** `"result"` present. Secret is flagged on the response and stored in session memory.

### Turn 2 — leak attempt (blocked)

```bash
curl -s -X POST http://127.0.0.1:4444/ \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: lab-session-1" \
  -d '{
    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": {"name": "send_email", "arguments": {"body": "AKIAIOSFODNN7EXAMPLE"}}
  }' | python3 -m json.tool
```

**Expected:** `"error"` with message containing *already appeared in an earlier tool response*.

### Verify audit + propagation

```bash
sluice logs --since 10m --json | head
```

Look for `rule: taint_leak` and `detectors: ["taint_leak"]`.

In v0.3, propagation metadata (source tool, JSON path hash) is stored in the audit DB `propagation_edges` table and attached to the blocking event.

---

## 6. Cursor integration (stdio)

Sluice replaces the MCP server command in your editor config.

### Step 1 — Prepare config in a stable path

```bash
mkdir -p ~/.sluice
sluice init --path ~/.sluice/config.yaml
```

Edit `~/.sluice/config.yaml` upstreams to point at your real MCP server. Example for filesystem:

```yaml
upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/YOU/projects"]
```

### Step 2 — Cursor MCP config

Open Cursor → Settings → MCP (or edit `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "sluice",
      "args": ["stdio", "--config", "/Users/YOU/.sluice/config.yaml", "--upstream", "filesystem"]
    }
  }
}
```

Restart Cursor. Tools should appear as before, but traffic flows through Sluice.

### Step 3 — Validate in Cursor

1. Ask the agent to read a file you planted with a fake AWS key (`AKIAIOSFODNN7EXAMPLE`).
2. In another turn, ask it to paste that value into a different tool call (email, HTTP, write).
3. The second call should fail at the MCP layer.

Check logs:

```bash
sluice logs --since 30m
```

---

## 7. Claude Desktop integration (stdio)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "sluice",
      "args": [
        "stdio",
        "--config", "/Users/YOU/.sluice/config.yaml",
        "--upstream", "filesystem"
      ]
    }
  }
}
```

Restart Claude Desktop. Same validation steps as Cursor.

---

## 8. Policy presets

Bundled presets ship rules for common MCP servers. You do not write YAML from scratch.

```bash
sluice presets list
sluice presets show github
sluice presets apply github --path config.yaml
```

Available presets: `filesystem`, `github`, `slack`, `postgres`, `brave-search`.

In `config.yaml`, use:

```yaml
include:
  - preset:github
  - preset:slack

upstreams:
  - name: github
    transport: streamable_http
    url: "https://api.github.com/mcp"
    headers:
      Authorization: "${GITHUB_TOKEN}"
```

`${VAR}` expansion reads from your environment. Unset variables cause `sluice doctor` / `sluice serve` to fail fast with a clear error.

---

## 9. Configuration reference

| Section | Purpose |
|---|---|
| `include` | Pull in preset YAML or local override files |
| `proxy` | Bind host/port for `sluice serve` |
| `upstreams` | MCP servers (stdio, http, streamable_http) |
| `routing.default` | Default upstream when path is `/` |
| `detectors` | Enable/disable scanner categories |
| `policy.rules` | First-match rules: detector pattern, upstream, tool, action |
| `taint` | Session memory; `provenance: true` enables JSON-path tracking (v0.3) |
| `dashboard` | HTML UI at `/_sluice/` |
| `audit` | SQLite path, stdout, or both |
| `otel` | Optional OpenTelemetry trace export |
| `transports.streamable_http` | SSE buffer size and idle eviction |

### Policy actions

| Action | Request | Response |
|---|---|---|
| `block` | Return error, upstream not called | Return error to agent |
| `redact` | Strip sensitive substrings, forward | Strip and forward; values marked for taint |
| `flag` | Forward; log hit | Forward; values marked for taint |
| `pass` | Ignore hit | Ignore hit |

Taint marks are created on **response** hits when action is `flag` or `redact`.

---

## 10. CLI reference

```bash
sluice init [--path config.yaml] [--force]
sluice serve [--config PATH] [--host HOST] [--port PORT]
sluice stdio [--config PATH] [--upstream NAME]
sluice logs [--since 1h] [--upstream NAME] [--action block] [--json]
sluice doctor [--config PATH]
sluice version [--json]
sluice presets list|show|apply
```

### Health checks

```bash
sluice doctor
curl http://127.0.0.1:4444/health
curl http://127.0.0.1:4444/_sluice/health
```

---

## 11. Dashboard

When `dashboard.enabled: true` (default on loopback):

| URL | Purpose |
|---|---|
| `/_sluice/` | 24h overview: actions, detectors, sessions |
| `/_sluice/events` | Filterable event list |
| `/_sluice/sessions` | Sessions with taint mark counts |

Optional bearer auth:

```yaml
dashboard:
  enabled: true
  token: "${SLUICE_DASHBOARD_TOKEN}"
```

Then: `curl -H "Authorization: Bearer $SLUICE_DASHBOARD_TOKEN" http://127.0.0.1:4444/_sluice/`

---

## 12. OpenTelemetry (optional)

Install OTel extras:

```bash
pip install "sluice-taint[otel]"
```

Enable in config:

```yaml
otel:
  enabled: true
  endpoint: "http://localhost:4318/v1/traces"
  service_name: "sluice"

audit:
  sink: all    # sqlite + stdout + otel
```

Each policy decision exports a span with `sluice.action`, `sluice.detectors`, `sluice.rule`, and propagation attributes when present.

---

## 13. Custom detectors

See [docs/detectors.md](detectors.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).

Quick path for a third-party package:

```toml
[project.entry-points."sluice.detectors"]
my_detector = "my_pkg.detectors:MyDetector"
```

Implement `scan(text, context) -> list[Hit]` and add a matching `policy.rules` entry.

---

## 14. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `command not found: sluice` | pip bin not on PATH | `python3 -m sluice version` or add `~/.local/bin` to PATH |
| `environment variable not set` | `${VAR}` in config | Export the variable or remove the reference |
| Upstream tools missing in Cursor | Wrong `--upstream` or broken npx | Run `sluice doctor`; test upstream without Sluice first |
| Taint not blocking | Different `Mcp-Session-Id` per request | Use the same session header (HTTP) or same stdio session |
| Taint not blocking | `min_length` too high | Lower `taint.min_length` (default 12) |
| Taint not blocking | Policy uses `block` on response | Use `flag` or `redact` on response so values are remembered |
| Dashboard 404 | Disabled or wrong path | Set `dashboard.enabled: true`; check `dashboard.path` |
| Docker stdio fails | By design | Use pip install for desktop clients |

### Debug logging

```bash
sluice serve --log-level debug
```

Audit rows never store raw secrets — only redacted previews and hashed propagation metadata.

---

## 15. Security notes

- Sluice is a **local** gate. It does not phone home.
- Bind to `127.0.0.1` unless you set `dashboard.token` for remote binds.
- Taint v0.3 uses substring matching with JSON-path provenance. It is fast and deterministic, not a full data-flow analysis engine.
- Report vulnerabilities per [SECURITY.md](../SECURITY.md).

---

## 16. Suggested test checklist

Use this before trusting Sluice in a real workflow:

- [ ] `sluice version` prints 0.3.0
- [ ] `sluice doctor` reports all upstreams ok
- [ ] Outbound secret blocked (`curl` test in §4)
- [ ] Taint leak blocked across two calls with same session (§5)
- [ ] `sluice logs` shows `block` and `taint_leak` rows
- [ ] Dashboard loads at `/_sluice/`
- [ ] Cursor or Claude Desktop shows tools through `sluice stdio`
- [ ] `sluice presets list` shows five presets
- [ ] `bash scripts/demo.sh` completes without error

When all items pass, you have validated Sluice end to end.

---

## 17. Next steps

- Tune `policy.rules` per upstream and tool name (`tool: send_*`)
- Add `include: preset:github` (etc.) for production MCP servers
- Point `audit.sqlite.path` at a persistent volume in Docker
- Wire OTel into your existing observability stack

For architecture detail see [Architecture.md](../Architecture.md). For the roadmap see [POC_PLAN.md](../POC_PLAN.md).
