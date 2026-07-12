# ADR 0002: First-match semantics for policy rules

Status: Accepted
Date: 2026-06-04 (backfilled 2026-07-11)
Deciders: krishna, colleague

## Context

Users write policy as a YAML list of rules. Each rule has a detector selector, optional upstream/tool scoping, and an action (`block`, `redact`, `flag`). When a JSON-RPC message hits multiple rules, we need deterministic semantics for which action applies.

Two credible models:

1. **First match wins.** Evaluate rules top-to-bottom; the first that applies decides the action.
2. **Most-severe match wins.** Evaluate all matching rules; pick the strictest action (`block` > `redact` > `flag`).

Both have real users behind them (nginx and iptables use first-match; some SAST tools use most-severe).

Constraints for us:
- Rules are user-authored YAML, so debuggability matters (`which rule fired?` should be trivial to answer)
- We want to allow user overrides of preset rules cleanly in v0.2
- We do not want a policy language, only a rule list

## Decision

**First match wins.** Rules are evaluated top-to-bottom; the first rule whose selector matches the current event's detector+upstream+tool determines the action. A trailing `default_action:` applies if nothing matched.

## Consequences

- Debuggability is trivial: the audit log records the rule index and text, and users can literally count from the top.
- Overriding a preset in v0.2 is natural — user rules go before preset rules in the resolved list, so a user's `flag` rule at position 0 can override a preset's `block` rule at position 5.
- Users can foot-gun themselves by writing a broad `flag` rule at the top and shadowing narrower `block` rules below. Documented in the policy guide as a known trap.
- Rule authors must think about order, not just semantics — some added cognitive cost.
- No policy compiler needed; no DAG to reason about.

## Alternatives considered

- **Most-severe wins.** Safer default (hardest action wins any conflict), but harder to reason about ("why did this rule not fire? Oh, another rule fired more strictly elsewhere"). Rejected on debuggability.
- **Rule priorities as explicit integers.** More powerful but requires users to reason about a priority space instead of a list. Rejected as over-engineered for v0.1.
- **First-match with explicit `stop:` marker.** Would let users continue evaluation after a match. Rejected — no v0.1 use case, adds surface.
