# ADR 0005: Publish as `sluice-taint` on PyPI

Status: Accepted
Date: 2026-07-09 (backfilled 2026-07-11)
Deciders: krishna, colleague

## Context

We chose the project name **Sluice** — the metaphor of "flow control on the wire" fit the taint-propagation wedge, and no obvious trademark conflicts came up. Repo is `sluice`, CLI binary is `sluice`.

When we went to publish the PyPI package under the same name, the project name `sluice` was already taken by an unrelated package. PyPI does not allow name reuse.

Options:
- **`sluice-taint`** — communicates the wedge, dashes are ergonomic.
- **`sluice-mcp`** — communicates the domain, more discoverable via keyword search.
- **`sluice-proxy`** — describes the shape but hides the wedge.
- **`mcp-sluice`** or **`pysluice`** — awkward.
- **Rename the project entirely** — huge cost for a name we already like.

## Decision

Publish as **`sluice-taint`**. Keep the repo, CLI binary, and README identity as `sluice`. Document the mismatch explicitly in the README install section.

## Consequences

- Three names in play: repo `sluice`, CLI `sluice`, PyPI `sluice-taint`. Users installing for the first time see the mismatch and may briefly wonder if this is a partial product.
- The name reinforces the differentiator (taint) at the pip layer, which is the layer where discovery-by-keyword-search happens.
- README explains it in one sentence, so the friction is bounded.
- If PyPI ever frees up the `sluice` name (unlikely), we can migrate — but existing installers would break, so we would keep `sluice-taint` as an alias forever.

## Alternatives considered

- **`sluice-mcp`.** Better SEO for the MCP audience. Rejected because "taint" is the wedge, not "MCP" (many projects target MCP; only Sluice tracks taint).
- **Rename to `Tollbooth` or `Passport-MCP`.** Rejected — Sluice as a name is genuinely good and rebranding to work around one PyPI taken name is bad ROI.
- **Contact the existing `sluice` PyPI owner.** Considered; abandoned because the existing project appears semi-abandoned but the owner is unresponsive, and even if it worked it's a slow path with uncertain outcome.

## Follow-up

- README install section calls the mismatch out
- No plans to publish a placeholder package under `sluice-mcp` or any other alt name to prevent squatters — deferred until we see actual confusion
