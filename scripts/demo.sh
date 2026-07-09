#!/usr/bin/env bash
# Demo: Sluice blocks a credential in a tool call.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v sluice >/dev/null 2>&1; then
  pip install -e ".[dev]" -q
fi

sluice init --force --path /tmp/sluice-demo-config.yaml

cat >/tmp/sluice-demo-upstream.py <<'PY'
import json, sys
for line in sys.stdin:
    req = json.loads(line)
    print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}), flush=True)
PY

python3 <<'PY'
import yaml
from pathlib import Path
p = Path("/tmp/sluice-demo-config.yaml")
data = yaml.safe_load(p.read_text())
data["upstreams"] = [{
    "name": "demo",
    "transport": "stdio",
    "command": "python3",
    "args": ["/tmp/sluice-demo-upstream.py"],
}]
data["routing"] = {"default": "demo"}
p.write_text(yaml.dump(data, sort_keys=False))
PY

echo "Starting Sluice on :4444..."
sluice serve --config /tmp/sluice-demo-config.yaml &
PID=$!
sleep 2

echo ""
echo "Blocked request (expect JSON-RPC error):"
curl -s -X POST http://127.0.0.1:4444/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"content":"AKIAIOSFODNN7EXAMPLE"}}}' | python3 -m json.tool

kill "$PID" 2>/dev/null || true
echo ""
echo "Done."
