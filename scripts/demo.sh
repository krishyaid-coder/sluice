#!/usr/bin/env bash
# Demo: secret block + taint leak across two tool calls.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v sluice >/dev/null 2>&1; then
  pip install -e ".[dev]" -q
fi

CONFIG=/tmp/sluice-demo-config.yaml
MOCK=/tmp/sluice-demo-mock.py
PORT=4444

cat >"$MOCK" <<'PY'
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
    if not line.strip():
        continue
    req = json.loads(line)
    if req.get("method") == "notifications/initialized":
        continue
    out = respond(req)
    if out:
        print(json.dumps(out), flush=True)
PY

write_config() {
  local action="$1"
  python3 <<PY
import yaml
from pathlib import Path
data = {
    "version": 1,
    "proxy": {"host": "127.0.0.1", "port": $PORT},
    "upstreams": [{
        "name": "demo",
        "transport": "stdio",
        "command": "python3",
        "args": ["$MOCK"],
    }],
    "routing": {"default": "demo"},
    "policy": {
        "rules": [{"detector": "secrets.*", "action": "$action"}],
        "default_action": "pass",
    },
    "taint": {"enabled": True, "min_length": 12, "provenance": True},
    "dashboard": {"enabled": True},
    "audit": {
        "sink": "sqlite",
        "sqlite": {"path": "/tmp/sluice-demo-audit.db", "retention_days": 1},
    },
}
Path("$CONFIG").write_text(yaml.dump(data, sort_keys=False))
PY
}

start_sluice() {
  sluice serve --config "$CONFIG" --port "$PORT" &
  PID=$!
  sleep 2
}

stop_sluice() {
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
}

echo "=== Part 1: Direct secret in outbound call (policy: block) ==="
write_config block
start_sluice
curl -s -X POST "http://127.0.0.1:${PORT}/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"body":"AKIAIOSFODNN7EXAMPLE"}}}' \
  | python3 -m json.tool
stop_sluice

echo ""
echo "=== Part 2: Taint leak (policy: flag on response, block on reuse) ==="
write_config flag
start_sluice
SESSION=demo-session-1
HDR=(-H "Content-Type: application/json" -H "Mcp-Session-Id: $SESSION")

echo "--- read_file plants secret (allowed) ---"
curl -s -X POST "http://127.0.0.1:${PORT}/" "${HDR[@]}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}' \
  | python3 -m json.tool

echo "--- send_email reuses secret (taint_leak) ---"
curl -s -X POST "http://127.0.0.1:${PORT}/" "${HDR[@]}" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_email","arguments":{"body":"AKIAIOSFODNN7EXAMPLE"}}}' \
  | python3 -m json.tool

echo ""
echo "=== Audit tail ==="
sluice logs --config "$CONFIG" --since 5m --limit 10

echo ""
echo "Dashboard: http://127.0.0.1:${PORT}/_sluice/"
stop_sluice
echo "Done."
