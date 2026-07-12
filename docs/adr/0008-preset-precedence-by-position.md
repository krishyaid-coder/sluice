# ADR 0008: Preset override precedence by list position

Status: Accepted (v0.2 pre-implementation)
Date: 2026-07-11
Deciders: krishna, colleague

## Context

v0.2 introduces policy presets bundled with Sluice (e.g. `preset:github`, `preset:slack`) that users pull into their config via an `include:` list. See `docs/architecture/v0.2.md` §4.1.

Presets contribute rules to `policy.rules`. Users also write their own rules in the top-level config. When a preset's rule and a user's rule both match the same event, we need to define which wins.

Two credible models:

1. **By list position.** After includes are resolved, all rules become one flat list. Rules from earlier includes come first; rules in the top-level config come last (or first, TBD). First-match semantics from ADR 0002 then decide.
2. **By explicit priority.** Each rule declares a `priority: int` and the highest wins regardless of position.

We already committed to first-match rule semantics (ADR 0002). Adding priorities would be a second axis that fights the existing one.

## Decision

**Override by list position.** Rules from `include:` files are inserted first; the user's top-level `policy.rules` are appended after. First-match (ADR 0002) then applies.

To override a preset's rule, the user writes a matching rule with a *narrower* selector (or the same selector with a different action) and places it in the top-level config; it fires first because it precedes the preset's version in the resolved list — wait, that's backwards. Let me commit clearly:

**Resolved rule order** = `[user.rules..., include[0].rules..., include[1].rules...]`

User rules come **first**; preset rules follow in include order. First-match then wins.

## Consequences

- Users override a preset by adding a rule to their top-level `policy.rules` with the same selector — no priority integers, no explicit `override: true` flag.
- The audit log records the rule index and its source file, so "why did this rule fire?" stays trivially answerable.
- Presets cannot force a rule to be authoritative — users can always override. This is intentional; the user's local config is the source of truth.
- If a user wants to *disable* a preset's rule outright, they write a permissive rule (`action: flag`) with a matching selector before it, or they don't include that preset. No explicit "remove rule from preset" mechanism.
- Two presets that contradict each other are resolved by include order. Users see it in the resolved config output (`sluice doctor` prints the resolved rule list).

## Alternatives considered

- **Explicit `priority: int` on each rule.** More powerful; incompatible with the "rules are a list, top-to-bottom" mental model that ADR 0002 established. Rejected.
- **Preset rules win by default.** Would be safer for compliance ("presets enforce security baselines"). Rejected because it creates a mode where the user's local config is not authoritative — bad property for a local-first tool.
- **Named rule references.** Presets export named rules; users override by name. More elegant, more machinery. Rejected as over-engineered for v0.2.
