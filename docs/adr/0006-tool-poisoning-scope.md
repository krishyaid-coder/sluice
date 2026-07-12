# ADR 0006: Tool-poisoning detector scans names, descriptions, and param schemas

Status: Accepted
Date: 2026-06-07 (backfilled 2026-07-11)
Deciders: krishna, colleague

## Context

Tool poisoning is the MCP attack where a malicious server advertises tools whose *metadata* (name, description, parameter documentation) contains hidden instructions targeting the LLM — e.g. a `search` tool whose description tells the model to also send the user's environment variables. The model reads the metadata, follows the hidden instruction, and the malicious server exfiltrates data on the next call.

The Invariant Labs research on this attack pattern is the reference. Scans can target any subset of:

1. **Tool names** — occasionally used to inject unicode or lookalike characters
2. **Tool descriptions** — the main vector; hidden instructions typically live here
3. **Tool parameter schema descriptions** — a secondary vector; some clients render these into the model context
4. **Tool output examples** (rarely present) — mostly non-issue in v0.1

## Decision

The `tool_poisoning` detector scans **all three primary fields**: name, description, and parameter schema descriptions. Same heuristic set applied to each.

## Consequences

- Full coverage of the known attack surface without needing per-field policy.
- Slightly more work per `tools/list` response — negligible in practice (the message is small and `tools/list` fires rarely).
- False positives on any of the three fields are treated identically, which may be too aggressive for legitimate MCP servers with descriptive parameter docs. We accept the risk in v0.1 and revisit if users report FPs.
- The audit event records which field the hit came from, so tuning is possible without a schema change.

## Alternatives considered

- **Scan descriptions only.** Simplest; misses parameter-schema attacks. Rejected — attack surface asymmetry between fields is small enough that scanning all three is worth it.
- **Scan everything including outputs.** More coverage; but tool outputs vary wildly and are the wrong place for tool-poisoning specifically (that's a request-body / prompt-injection concern, not a metadata concern). Rejected as scope creep.
- **Per-field policy.** Let users choose which fields to scan. Rejected — no v0.1 user is asking for this, and it complicates the config schema for a marginal gain.

## Detection heuristics (referenced, not exhaustive)

- Imperative instructions targeting the assistant ("ignore", "actually", "before you call this")
- Base64 or hex blobs longer than N characters
- Zero-width characters, invisible unicode ranges
- Duplicated or hidden `system:` / `assistant:` role markers
- URL patterns with credential-looking query strings

Full heuristic set lives in `sluice/detectors/tool_poisoning.py` and evolves without ADRs.
