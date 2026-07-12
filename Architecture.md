# Sluice Architecture

Sluice is a local MCP gate with three jobs: move JSON-RPC between client and tool servers, judge every message against policy, and remember sensitive values for the rest of the session.

The design splits **transport** (how bytes move), **pipeline** (what to allow), and **router** (which upstream to call). Policy logic lives in exactly one place so stdio and HTTP never drift apart.

**Current release:** v0.3.0 (PyPI: `sluice-taint`)

## System view

```
+------------------+          +------------------------------------------+
|  MCP client      |          |  Sluice process                          |
|  (Cursor, Claude,|  stdio   |                                          |
|   custom agent)  +--------->+  Transport (stdio / HTTP / SSE)          |
|                  |   or     |         |                                |
|                  |  HTTP    |         v                                |
+------------------+          |  Pipeline (single enforcement point)     |
                              |    1. recall check (carryover memory)    |
                              |    2. detector scan                      |
                              |    3. policy action                      |
                              |    4. mark values on responses           |
                              |         |                    |           |
                              |         |                    v           |
                              |         |         Audit (SQLite / OTel)  |
                              |         v                                |
                              |  Router  +  Dashboard (/_sluice/)        |
                              |    pick upstream by name                 |
                              |         |                                |
                              +---------+----------------------------------+
                                        |
                    +-------------------+-------------------+
                    v                   v                   v
              filesystem MCP      github MCP           postgres MCP
              (stdio child)       (streamable HTTP)    (HTTP)
```

One Sluice process can front several upstreams. In HTTP mode the client picks the upstream with the URL path (`/u/<name>`). In stdio mode one upstream is selected from config.

## Request path (agent to tool)

Every outbound JSON-RPC message walks the same steps.

**Step 1. Transport receives the frame.** stdio reads a line from stdin. HTTP reads a POST body. SSE uses `GET /u/<name>` with session headers.

**Step 2. Pipeline runs recall check.** If the message body contains a value already stored for this session, Sluice returns a JSON-RPC error with rule `taint_leak`. The upstream is never contacted. v0.3 records a propagation edge in the audit log (source tool/path hash → sink tool).

**Step 3. Pipeline runs detectors.** Pure text scanners look for credentials, PII, tool-poisoning patterns (on `tools/list`), and prompt-injection phrases (on tool responses).

**Step 4. Policy engine picks an outcome.** Rules in `config.yaml` are matched top to bottom. Each rule can scope to a detector pattern, upstream name, and tool name. Outcomes are `block`, `redact`, `flag`, or `pass`. Bundled presets can be included via `include: preset:<name>`.

**Step 5. Router forwards if allowed.** On `block`, the pipeline stops and returns an error. On `redact`, sensitive substrings are stripped and the cleaned body is forwarded. On `flag`, the message goes through unchanged.

**Step 6. Audit row is written.** Every decision is stored locally with session id, upstream, direction, method, tool, action, detector ids, and optional preset source. Raw secrets are never persisted.

## Response path (tool to agent)

The return trip mirrors the outbound path.

**Step 1.** Router receives the upstream JSON-RPC response.

**Step 2.** Pipeline scans the response with the same detectors and policy rules.

**Step 3.** If the outcome is `flag` or `redact`, matched values are added to session carryover memory. v0.3 also records JSON paths when `taint.provenance: true`.

**Step 4.** The (possibly redacted) response is sent back through the transport. Another audit row is written.

## Carryover memory

**v0.1:** literal substring matching per session id.

**v0.3 (taint v2):** same substring recall, plus JSON-path provenance and a `propagation_edges` table in SQLite. When a leak is blocked, the audit event links source tool/path to sink tool.

Still intentionally heuristic: fast, deterministic, no ML. Not a full data-flow analysis engine.

## Module map

| Path | Responsibility |
|------|----------------|
| `cli/main.py` | Commands: init, serve, stdio, logs, doctor, version, presets |
| `cli/presets.py` | `sluice presets list|show|apply` |
| `config/schema.py` | Pydantic models for `config.yaml` |
| `config/loader.py` | Load, validate, `${VAR}` expansion, legacy migration |
| `config/presets.py` | Resolve `include:` and bundled preset YAML |
| `policy/presets/*.yaml` | Curated rules per MCP server vendor |
| `proxy/transports/http.py` | FastAPI listener, SSE proxy, dashboard mount |
| `proxy/transports/stdio.py` | stdin/stdout bridge for desktop MCP clients |
| `proxy/transports/streamable_http.py` | Per-session SSE buffer + reconnect replay |
| `proxy/pipeline.py` | Recall check, scan, policy, audit hooks |
| `proxy/router.py` | Spawn stdio children or call HTTP upstreams |
| `detectors/` | secrets, PII, tool_poisoning, prompt_injection |
| `policy/engine.py` | Map detector hits to block / redact / flag |
| `session/store.py` | Per-session carryover memory + provenance |
| `session/provenance.py` | JSON-path extraction, propagation edges |
| `audit/sqlite.py` | Durable decision log at `~/.sluice/audit.db` |
| `audit/otel.py` | Optional OpenTelemetry span export |
| `dashboard/` | Server-rendered HTML at `/_sluice/` |

## Config model

`config.yaml` drives everything. No code change is required to add a rule.

Key sections: `include`, `upstreams`, `policy`, `taint`, `dashboard`, `audit`, `otel`, `transports.streamable_http`.

See [config.yaml.example](config.yaml.example) and [docs/guide.md](docs/guide.md).

## Invariants

Transports never call detectors directly.

Detectors never perform I/O. Text in, hits out.

The pipeline is shared by stdio and HTTP.

Audit data stays on disk locally unless you opt into OTel export.

Policy is data in YAML, not forks of the core package.

## Known limitations (v0.3)

- SSE session buffers are in-process only (no cross-worker persistence).
- Taint recall is substring-based; provenance is best-effort JSON-path tagging.
- Docker deployment is HTTP-only; desktop clients use `pip install` + stdio.
- No LLM-based classification. All detectors are heuristic.

For forward-looking design see [docs/architecture/v0.2.md](docs/architecture/v0.2.md).
