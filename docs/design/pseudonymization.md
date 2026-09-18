# Pseudonymization

Sluice supports a third policy action for PII, beyond `block` and `redact`:
`pseudonymize`. This document explains what it does, what it does not do,
and the specific limitations users should understand before deploying it.

**Status:** shipped in v0.4 (Version B is a full round-trip). Session-scoped,
PII-only, fail-closed on reverse.

---

## The problem it solves

Real workflows need agents to reason about sensitive data without exposing
that data to the underlying LLM. Two examples:

- A support agent needs to look up a customer's ticket, understand the
  situation, and reply to the customer without the LLM ever seeing the
  customer's real name, email, or credit-card last-four.
- A meeting scheduler needs to see a team's contact list, find a common
  slot, and send invites — without the LLM ever seeing real email addresses.

The existing `block` and `redact` actions both prevent the agent from doing
useful work: block stops the call, redact strips the values so the agent
can't reference them coherently.

Pseudonymization replaces real values with stable placeholders. The agent
sees `EMAIL_A` instead of `jane@corp.com`, and can send an email to
`EMAIL_A`. On the way out to the tool server, Sluice substitutes the real
value back.

---

## How it works

Two passes, one per direction.

### Forward pass — on tool responses

When a `tools/call` response comes back from a tool server, the pipeline
runs the PII detectors. If a rule with `action: pseudonymize` matches a
hit, the engine:

1. Looks up the real value in the session's `PseudonymRegistry`.
2. If not present, assigns the next pseudonym for that type
   (`EMAIL_A`, `EMAIL_B`, …, `EMAIL_Z`, `EMAIL_AA`, `EMAIL_AB`, …).
3. Replaces the real value in the response body with the pseudonym.
4. Forwards the modified body to the client.

Type prefix comes from the detector id: `pii.email` → `EMAIL`,
`pii.phone_sg` → `PHONE`, `pii.credit_card` → `CARD`, etc.

Two requirements guaranteed here:

- **Stable within a session.** The same real value always gets the same
  pseudonym. The AI can reference `EMAIL_A` many turns later and it still
  means the same person.
- **Fresh across sessions.** New session, new registry, new alphabet.
  Nothing persists to disk.

### Reverse pass — on tool requests

Before an outbound `tools/call` reaches the tool server, the pipeline:

1. Scans the request body for pseudonym-shaped tokens
   (`EMAIL_A`, `PHONE_AB`, etc.) whose type prefix is a recognized PII type.
2. For each match, looks up the real value in the session's registry.
3. If any pseudonym is not in the registry:
   - **Fail-closed (default):** block the call with a clear error.
   - **Fail-open (opt-in):** let the message through unchanged.
4. Otherwise, substitutes the real value for each pseudonym and forwards
   the message to the tool server.

The forward pass happens inside the policy engine (`evaluate`). The reverse
pass happens in the pipeline before the engine runs, so downstream logic
sees the real values.

---

## Configuration

```yaml
policy:
  rules:
    - detector: "pii.*"
      action: "pseudonymize"

pseudonym:
  enabled: true
  fail_closed_on_reverse: true
  scheme: "type_alpha"
```

- `enabled`: master switch. When `false`, `pseudonymize` actions fall back
  to `redact` behaviour so no PII leaks even if the feature is off.
- `fail_closed_on_reverse`: block outbound calls containing unknown
  pseudonym-shaped tokens. Default `true`. Only set `false` if you have
  understood the trade-off.
- `scheme`: reserved for future extensions. Only `type_alpha` today.

---

## Interactions with other Sluice features

### Taint

If pseudonymization is doing its job, the AI never sees real values, so
`taint_leak` should be a rare fallback. But there is still an interaction
worth spelling out.

- **Reversed pseudonyms are exempt from taint check on the same message.**
  When the reverse pass substitutes `EMAIL_A` for `jane@corp.com`, the
  resulting message may contain `jane@corp.com` even though that value is
  in the taint store from earlier. Taint check is skipped for that
  message because the user explicitly opted into the pseudonymized round
  trip.
- **The AI writing a raw value directly still triggers taint.** If the AI
  writes `jane@corp.com` directly in an outbound tool call (rather than
  via a pseudonym), the reverse pass finds no pseudonyms, does not skip
  taint, and taint blocks as usual.

### Redact

`redact` and `pseudonymize` are alternatives per rule. A single message
with both a PII hit and a secret hit under a `pseudonymize` rule:

- PII gets a pseudonym
- Secrets still get redacted (`[REDACTED-AWS_ACCESS_KEY]` etc.)

This keeps mixed messages safe: no secret quietly leaks under the guise
of pseudonymization.

### Direction

`pseudonymize` only takes effect on **response** direction (tool → client).
On request direction (client → tool), the engine coerces `pseudonymize` to
`flag`. Rationale: the reverse pass in the pipeline has already substituted
any pseudonyms back; the remaining PII in an outbound request is AI-authored
and needs a different treatment (block or redact rules) if the user wants
to gate it. This avoids the loop where the engine would pseudonymize the
value that the pipeline just reversed.

---

## Known limitations

### The user may see pseudonyms in the AI's chat text

Sluice sits between the MCP client and the MCP tool servers. It does *not*
intercept the AI's chat response back to the user. If the AI reads a
pseudonymized tool response and then writes *"I emailed EMAIL_A about the
meeting"* to the user, the user will see `EMAIL_A` in the chat.

The **real email is still sent** to `jane@corp.com` Sluice restored the
real value on the outbound tool call. But the AI's user-facing chat text
may reference the pseudonym.

This is an architectural consequence of proxying at the MCP layer. Closing
it would require a Claude Desktop extension that intercepts the chat pane,
which is out of scope for Sluice.

### Session-scoped only

Pseudonym registries live per session and do not persist. A new session
gets a fresh alphabet. This is deliberate for v1 (simpler mental model,
no cross-session data leakage). Persistent per-project mappings could be
a v2 feature if requested.

### PII only

Pseudonymization applies to PII detectors only. Secrets (API keys, tokens,
PEM blocks) are not pseudonymized because the failure mode of a
mistranslated token is far worse than a mistranslated email. A wrong email
gets rejected; a wrong token may authenticate a wrong request. Secrets
follow the redact/block paths.

### Pseudonym token collisions with real content

The reverse pass filters to a fixed set of known type prefixes
(`EMAIL`, `PHONE`, `SSN`, `CARD`, etc.) so ordinary code constants like
`CONSTANT_VALUE` are not misidentified as pseudonyms. But if real user
content happens to contain a token that matches — say a user writes
`EMAIL_Z` in a message when no such pseudonym exists — the fail-closed
mode will block the outbound call.

This is intentional: fail-closed is what a security tool should do when
in doubt. Users who want the message to pass through can either set
`fail_closed_on_reverse: false` (accepting more risk) or annotate the
value.

### Nested JSON

The reverse pass currently operates on the raw string form of the
JSON-RPC body. This works because pseudonym tokens are distinctive enough
to substitute reliably even inside a JSON string, but it does mean
pseudonyms embedded in unusual escape sequences (escaped quotes within
strings, base64-encoded bodies, deeply nested structures) may not be
detected. If you hit a case where this matters, please open an issue with
a repro.

---

## Performance

Pseudonymization adds a small forward-pass cost (dictionary lookup per PII
hit) and a small reverse-pass cost (regex scan + dictionary lookup per
outbound message). No measured impact on the 0.02 ms clean-path p50
overhead. When PII is present, expect similar per-hit latency to the
redact path, both do a substring replace.

---

## Threat model

**In-scope:**
- Preventing the LLM from ever seeing raw PII values that appear in tool
  responses
- Enabling the LLM to still take action on those values via stable
  pseudonyms
- Detecting outbound calls that reference pseudonyms not in the session
  registry (fail-closed)

**Out-of-scope:**
- Preventing pseudonym leakage into user-facing chat text (see limitations)
- Persistent cross-session identity (session-scoped only)
- Adversarial content that deliberately mimics pseudonym tokens to trick
  the reverse pass into incorrect substitutions (design does not defend
  against this the token set is not authenticated)
- Timing side-channels that might reveal registry size

---

## Migration notes

Existing configs continue to work. `pseudonymize` is a new opt-in action;
no rule uses it by default. To enable, add a rule like:

```yaml
policy:
  rules:
    - detector: "pii.*"
      action: "pseudonymize"
```

Test in a non-production session first to see how your typical agent flow
interacts with the substitutions.
