# Sluice Architecture

Sluice is a local MCP gate with three jobs: move JSON-RPC between client and tool servers, judge every message against policy, and remember sensitive values for the rest of the session.

The design splits **transport** (how bytes move), **pipeline** (what to allow), and **router** (which upstream to call). Policy logic lives in exactly one place so stdio and HTTP never drift apart.

## System view

```
+------------------+          +------------------------------------------+
|  MCP client      |          |  Sluice process                          |
|  (Cursor, Claude,|  stdio   |                                          |
|   custom agent)  +--------->+  Transport                               |
|                  |   or     |    read/write JSON-RPC frames            |
|                  |  HTTP    |         |                                |
+------------------+          |         v                                |
                              |  Pipeline (single enforcement point)     |
                              |    1. recall check (carryover memory)    |
                              |    2. detector scan                      |
                              |    3. policy action                      |
                              |    4. mark values on responses           |
                              |         |                    |           |
                              |         |                    v           |
                              |         |              Audit (SQLite)    |
                              |         v                                |
                              |  Router                                  |
                              |    pick upstream by name                 |
                              |         |                                |
                              +---------+----------------------------------+
                                        |
                    +-------------------+-------------------+
                    v                   v                   v
              filesystem MCP      github MCP           postgres MCP
              (stdio child)       (HTTP)               (HTTP)
```

One Sluice process can front several upstreams. In HTTP mode the client picks the upstream with the URL path (`/u/<name>`). In stdio mode one upstream is selected from config.

## Request path (agent to tool)

Every outbound JSON-RPC message walks the same steps.

**Step 1. Transport receives the frame.** stdio reads a line from stdin. HTTP reads a POST body. The transport does not interpret policy.

**Step 2. Pipeline runs recall check.** If the message body contains a value already stored for this session, Sluice returns a JSON-RPC error with rule `taint_leak`. The upstream is never contacted.

**Step 3. Pipeline runs detectors.** Pure text scanners look for credentials, PII, high-entropy strings, and (on `tools/list` responses) tool-poisoning patterns.

**Step 4. Policy engine picks an outcome.** Rules in `config.yaml` are matched top to bottom. Each rule can scope to a detector pattern, upstream name, and tool name. Outcomes are `block`, `redact`, `flag`, or `pass`.

**Step 5. Router forwards if allowed.** On `block`, the pipeline stops and returns an error. On `redact`, sensitive substrings are stripped and the cleaned body is forwarded. On `flag`, the message goes through unchanged.

**Step 6. Audit row is written.** Every decision is stored locally with session id, upstream, direction, method, tool, action, and detector ids. Raw secrets are never persisted.

## Response path (tool to agent)

The return trip mirrors the outbound path.

**Step 1.** Router receives the upstream JSON-RPC response.

**Step 2.** Pipeline scans the response with the same detectors and policy rules.

**Step 3.** If the outcome is `flag` or `redact`, matched values are added to session carryover memory. That is what enables the `read_file` then `send_email` block on the next outbound call.

**Step 4.** The (possibly redacted) response is sent back through the transport. Another audit row is written.

## Carryover memory

v0.1 stores literal substrings per session id. When a detector hit is flagged or redacted on a response, the matched text is kept in an in-memory set for that session. The next request checks that set before any new scanning.

This is intentionally simple: fast, deterministic, no ML. Future versions can add field-level provenance and a propagation graph in the audit log.

## Module map

| Path | Responsibility |
|------|----------------|
| `cli/main.py` | User-facing commands: init, serve, stdio, logs, doctor |
| `config/schema.py` | Pydantic models for `config.yaml` |
| `config/loader.py` | Load, validate, migrate legacy single-upstream configs |
| `proxy/transports/http.py` | FastAPI listener, multi-upstream paths |
| `proxy/transports/stdio.py` | stdin/stdout bridge for desktop MCP clients |
| `proxy/pipeline.py` | Recall check, scan, policy, audit hooks |
| `proxy/router.py` | Spawn stdio children or call HTTP upstreams |
| `detectors/` | Stateless scanners: secrets, PII, tool poisoning |
| `policy/engine.py` | Map detector hits to block / redact / flag |
| `session/store.py` | Per-session carryover memory |
| `audit/sqlite.py` | Durable decision log at `~/.sluice/audit.db` |

## Config model

`config.yaml` drives everything. No code change is required to add a rule.

An upstream entry names one MCP server and how to reach it (`stdio` command or `http` URL). The policy section lists rules evaluated in order. The taint section toggles carryover memory and sets a minimum match length. The audit section chooses SQLite, stdout, or both.

## Invariants

Transports never call detectors directly.

Detectors never perform I/O. Text in, hits out.

The pipeline is shared by stdio and HTTP.

Audit data stays on disk locally. No telemetry leaves the machine.

Policy is data in YAML, not forks of the core package.

## What v0.1 does not do yet

Full streamable HTTP session lifecycle (SSE) is stubbed.

Carryover memory is substring-based, not field-provenance.

No web dashboard. Use `sluice logs` for now.

No LLM-based classification. All detectors are heuristic.
