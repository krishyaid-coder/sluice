<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-lockup-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/logo-lockup.svg">
    <img src="docs/assets/logo-lockup.svg" alt="Sluice" width="280">
  </picture>
</p>

<p align="center">
  <em>The MCP gate that remembers what your agent already saw.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/sluice-taint/"><img src="https://img.shields.io/pypi/v/sluice-taint" alt="PyPI version"></a>
</p>

---

Agents do not just answer questions. They reach into files, databases, APIs, and inboxes through MCP. Each hop is another place data can end up where you did not intend.

Sluice is the gate on that path. It reads what goes out to tools and what comes back, applies your rules, and keeps a short memory of sensitive values for the rest of the conversation. If the model tries to ship the same value somewhere new, the gate stays shut.

## How it works

Every JSON-RPC message passes through one pipeline: recall check → detectors → policy → audit → router.

```mermaid
flowchart LR
    subgraph client [Your machine]
        A[Cursor / Claude / curl]
    end

    subgraph sluice [Sluice process]
        T[Transport\nstdio or HTTP]
        P[Pipeline\nscan + policy + taint]
        R[Router\npick upstream]
        D[Dashboard /_sluice/]
        DB[(audit.db)]
    end

    subgraph tools [MCP servers]
        F[filesystem]
        G[github]
        M[mock / others]
    end

    A -->|JSON-RPC| T
    T --> P
    P -->|allow| R
    P -->|block| T
    P --> DB
    R --> F
    R --> G
    R --> M
    F --> R
    G --> R
    M --> R
    R --> P
    P --> T
    T --> A
    D --> DB
```

| Component | Role |
|---|---|
| `config.yaml` | Upstreams, policy rules, taint, audit path |
| **Transport** | stdio for desktop clients; HTTP for servers and Docker |
| **Pipeline** | Taint recall, detector scan, policy action, audit write |
| **Router** | Forwards allowed messages to the right MCP upstream |
| **Detectors** | Secrets, PII, tool poisoning, prompt injection |
| **Taint store** | Remembers sensitive values per session; blocks reuse (`taint_leak`) |
| **Audit / dashboard** | SQLite log + browser UI at `/_sluice/` |

**Desktop (stdio):** `Cursor → sluice stdio → MCP server child process` · **Server (HTTP):** `curl / agent → :4444 → pipeline → upstream MCP`

## What this is (and what it is not)

Most MCP security tools work like a mailbox scanner. They open one envelope, look for a credit card or API key, and decide whether to let that single message through.

Sluice works like a gate with memory. It still scans every message, but it also remembers what sensitive data already entered the session. The second question it asks is different: has this exact value already been inside the conversation, and is it now trying to leave through another tool?

That second question is the whole point. A secret inside a `read_file` response can be legitimate. The same secret inside a later `send_email` call is a leak. Sluice blocks the second moment, not the first.

This is not a hosted service, not an LLM judge, and not a replacement for identity or network access control. It is a local runtime that sits on the MCP wire, enforces YAML policy, writes an audit log to disk, and fronts multiple tool servers from one config.

## A concrete case

Your agent calls `read_file` and the response includes `AKIAIOSFODNN7EXAMPLE`. That is fine. The file really contained it.

Two turns later it calls `send_email` and the body includes the same string. Sluice has no opinion about the first call. It stops the second one because the value already appeared inside this session and is trying to travel again.

<p align="center">
  <img src="docs/assets/demo.gif" alt="Sluice blocking a cross-tool leak" width="720">
</p>

Run it yourself: `bash scripts/demo.sh`

## v0.3.0

New in this release:

- Policy presets for filesystem, github, slack, postgres, brave-search (`sluice presets`)
- Read-only HTML dashboard at `/_sluice/`
- Docker image (`Dockerfile`) for HTTP deployments
- Integration tests against a mock MCP server in CI
- Taint v2: JSON-path provenance + propagation graph in audit log
- Prompt-injection detector on tool responses
- Optional OpenTelemetry exporter (`pip install sluice-taint[otel]`)
- Full streamable HTTP SSE reconnect with `Last-Event-Id`

**Full setup and validation guide:** [docs/guide.md](docs/guide.md)

### Demo

```bash
bash scripts/demo.sh
```

Shows Part 1 (secret blocked on outbound) and Part 2 (`read_file` → `send_email` blocked by `taint_leak`). See the video above, or [docs/demo-recording.md](docs/demo-recording.md) to record your own.

### Docker (HTTP mode)

```bash
sluice init
# edit config.yaml — set audit.sqlite.path to /var/lib/sluice/audit.db for persistence

docker compose up --build
# Sluice on http://localhost:4444, dashboard at http://localhost:4444/_sluice/
```

Pre-built images (after tag push): `ghcr.io/krishyaid-coder/sluice:latest`

```bash
docker run --rm -p 4444:4444 \
  -v "$PWD/config.yaml:/etc/sluice/config.yaml:ro" \
  -v sluice-audit:/var/lib/sluice \
  ghcr.io/krishyaid-coder/sluice:latest serve --config /etc/sluice/config.yaml --host 0.0.0.0
```

Desktop clients (Cursor, Claude) use `pip install sluice-taint` and `sluice stdio`, not Docker.

## v0.1.0

This release ships:

- stdio and HTTP transports with streamable HTTP (MCP 2025-03-26) for remote upstreams
- Carryover memory across tool calls (`taint_leak`)
- Secret, PII, and tool-poisoning detectors
- Per-upstream and per-tool YAML policy
- SQLite audit log and `sluice logs`
- CLI: `init`, `serve`, `stdio`, `logs`, `doctor`, `version`
- Legacy config migration to `config.yaml.upgraded`
- `${VAR}` expansion in config values

Quick demo script:

```bash
bash scripts/demo.sh
```

Performance on a developer laptop (pipeline only, 1 KB messages):

```
clean  p50=0.02 ms   p95=0.02 ms
secret p50=0.61 ms   p95=0.85 ms
```

Reproduce with `python -m sluice.bench.latency`.

## Install

```bash
pip install sluice-taint
```

PyPI package: [sluice-taint](https://pypi.org/project/sluice-taint/). The CLI command is still `sluice`.

## Get started

```bash
sluice init
sluice serve
```

The proxy listens on `127.0.0.1:4444` by default. Edit `config.yaml` before you point anything real at it.

### From source

```bash
git clone https://github.com/krishyaid-coder/sluice
cd sluice
pip install -e ".[dev]"
sluice init
sluice serve
```

## Hook up Claude Desktop or Cursor

Run Sluice as the MCP command instead of the tool server directly:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "sluice",
      "args": ["stdio", "--config", "/absolute/path/to/config.yaml"]
    }
  }
}
```

Sluice spawns the upstream named in your config and speaks MCP on stdin/stdout.

## Prove it works

With default policy, this should come back as a JSON-RPC error:

```bash
curl -s -X POST http://127.0.0.1:4444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "write_file",
      "arguments": {"content": "key=AKIAIOSFODNN7EXAMPLE"}
    }
  }' | jq
```

## Running multiple tool servers

HTTP mode can front more than one upstream. Send traffic to `POST /u/<upstream-name>` or `POST /` for the default route in `config.yaml`.

## Tooling

`sluice init` scaffolds config.

`sluice serve` starts the HTTP gate.

`sluice stdio` bridges one upstream over stdio for desktop clients.

`sluice logs --since 1h` prints recent decisions from the local SQLite log.

`sluice doctor` loads your config and reports obvious problems.

`sluice version` prints the build.

`sluice presets list|show|apply` manages bundled policy presets.

Open the dashboard at `http://127.0.0.1:4444/_sluice/` while `sluice serve` is running.

## Rules and outcomes

You declare what to do when a pattern fires: refuse the message (`block`), strip the match and continue (`redact`), or allow it but remember the value for later (`flag`).

Built-in matchers know common API keys, tokens, PEM blocks, email and phone shapes, cards and government IDs, noisy high-entropy strings, and suspicious text hiding inside `tools/list` payloads.

When a remembered value shows up again in an outbound call, the refusal reason is `taint_leak`.

Everything runs on your machine. Audit rows land in `~/.sluice/audit.db` unless you point them elsewhere.

## Architecture

See [Architecture.md](Architecture.md) for the full request path and module map.

## License

Apache 2.0
