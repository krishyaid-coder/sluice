# ADR 0004: Per-process session ID for stdio transport

Status: Accepted (revisit before multi-tenant support)
Date: 2026-06-06 (backfilled 2026-07-11)
Deciders: krishna, colleague

## Context

Session-scoped taint requires a session identifier. Streamable HTTP gets one for free from the `Mcp-Session-Id` header per MCP 2025-03-26. stdio has no such concept — the transport is just a pair of file descriptors between two processes.

We need *some* session ID for stdio so taint marks scope correctly. The realistic options are:

1. **One session ID synthesized at process start.** Each `sluice stdio` invocation is one session for its whole lifetime.
2. **New session ID per `initialize` request.** MCP clients send an `initialize` at handshake; treat each as starting a new session.
3. **No taint for stdio at all.** Punt.

Option 3 is a non-starter — stdio is our main path for Claude Desktop / Cursor, which is where taint matters most.

Option 2 sounds more correct but assumes the client re-initializes cleanly, which real clients don't necessarily do. It also breaks the mental model where "one desktop launch = one session."

## Decision

Synthesize **one session ID per `sluice stdio` process** (option 1). The ID is a `uuid4` generated at startup and stays constant until the process exits. Restarting `sluice stdio` starts a new session and clears its taint marks.

## Consequences

- Matches the intended use case (one Claude Desktop MCP entry runs one `sluice stdio` subprocess).
- Simple to reason about: "restart to reset taint."
- Not safe under any multi-tenant model where one `sluice stdio` process serves multiple end users. We don't intend to support that.
- If a client re-`initialize`s within one process, taint carries over — mildly incorrect but almost never observably wrong, since a re-`initialize` in practice means the same user starting fresh work.
- The session ID appears in the audit log, so users can grep to correlate events per stdio process instance.

## Alternatives considered

- **New session ID per `initialize`.** More semantically correct; more complex; not obviously worth the added edge cases in v0.1. Would require careful handling of taint eviction on `initialize`, and we don't yet have real data on how often clients re-initialize.
- **Session ID from environment variable.** Would let a wrapper script inject a stable ID across restarts. Rejected — no requester, no clear use case.

## When to revisit

If we ever support multi-tenant stdio (unlikely) or introduce a `sluice daemon` that hosts multiple stdio bridges under one process (possible in v0.3), this decision breaks and needs a new ADR.
