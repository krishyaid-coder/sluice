# Sluice Adoption Plan

How we get from "v0.1.0 is on PyPI" to "external humans are using it."

**Audience:** the two maintainers. Not intended for public consumption in its current form.

**Timebox:** 2 weeks from the day the demo GIF is committed. If we have no external user signal by the end of week 2, we pause building and revisit positioning before continuing to v0.2.

---

## 1. Current state

- v0.1.0 is on PyPI as `sluice-taint`
- Repo is public, no announcement made
- CI is green, docs are decent, README is publishable
- No demo GIF, no launch post, no external users yet (assumed)
- Positioning ("gate with memory") is sharp; needs harder framing for scrolling readers

---

## 2. Success criteria for the adoption sprint

Concrete, unambiguous. At least three of these by end of week 2:

- [ ] Demo GIF committed to repo + visible in README
- [ ] Launch post published somewhere real (HN, r/mcp, X, LinkedIn — one or more)
- [ ] 100+ GitHub stars **from people we can't personally identify**
- [ ] One unsolicited GitHub issue, PR, or discussion from an external person
- [ ] Mention (however small) in one MCP or LLM-security newsletter, roundup, or awesome-list
- [ ] One inbound message ("saw this, question about X") in email or DMs

The star count on its own is vanity. The star count *plus* one qualitative signal (issue, mention, DM) is real.

---

## 3. Demo GIF — the single highest-leverage action

Every hour without this is adoption revenue lost. Do it first.

### Storyboard (30 seconds, ~6 scenes)

1. **Terminal: `pip install sluice-taint`** (2s) — proves it's on PyPI
2. **Terminal: `sluice init` then `cat config.yaml`** (4s) — proves setup is 30 seconds
3. **Terminal: `sluice serve`** starts, dashboard log line visible (2s)
4. **Split view or cut: agent calls `read_file` returning content that includes an AWS-key-shaped string** (6s) — allowed, sluice logs "flagged"
5. **Agent calls `send_email` with body containing the same AWS key** (8s) — **blocked**, red JSON-RPC error rendered
6. **Terminal: `sluice logs --since 1m`** shows both events, second one marked `taint_leak` (6s)
7. **Freeze frame with tagline overlay**: *"Sluice — the gate on your MCP wire that remembers."* (2s)

The whole point is scene 5. Every frame before it exists to make scene 5 land.

### Capture instructions

- Tool: `asciinema` for the terminal parts, then `agg` to render GIF. Or `terminalizer`. Or record MP4 with QuickTime and convert. Whichever gives smallest file size at readable resolution.
- Target: under 4 MB, under 30 seconds, 1000-1200px wide. GitHub renders README GIFs at ~800px.
- Prompt: monospace font, dark background, 24pt+ — must be readable on mobile.
- Filename: `docs/assets/demo.gif` (create `docs/assets/` dir).
- README embed at the very top, above the current pitch paragraph:
  ```markdown
  ![Sluice demo](docs/assets/demo.gif)
  ```

### Backup: static screenshot

If GIF capture drags, ship a single annotated screenshot of the blocked `taint_leak` event now, replace with GIF when ready. A screenshot is 100x better than nothing.

---

## 4. Launch post drafts

**All drafts below are starting points, not final copy. Edit heavily to match your voice. Never post as-is.**

### 4.1 Hacker News — Show HN

**Title (60 char limit, no emoji, no punctuation flourish):**

> Show HN: Sluice – MCP proxy that blocks data exfiltration across tool calls

**Body (short — HN rewards brevity):**

> Hi HN — I built Sluice because MCP servers are proliferating and nobody has a clean answer to "what data actually leaves through my agent's tool calls."
>
> Most MCP security tools are stateless scanners: they open one JSON-RPC message, check it for secrets or PII, and move on. Sluice keeps a per-session memory of sensitive values it's seen in tool responses. If the agent tries to pass the same value out to another tool later — a secret read from a file, then written into an email — the second call gets blocked.
>
> Overhead is 0.02 ms p50 on the clean path (measured on a laptop, pipeline only, 1 KB messages). No LLM in the loop. All local, no telemetry.
>
> It's a stdio + HTTP + streamable HTTP proxy. Works with Claude Desktop, Cursor, or anything speaking MCP. Two-line config change to point your client at it.
>
> Repo: <URL>. Runs on 3.11+. Apache 2.0.
>
> Happy to answer questions about the taint algorithm, the false-positive story, or where it falls over.

**Timing:** Tuesday, Wednesday, or Thursday morning US Pacific. Not Monday (traffic burst), not Friday (dies over weekend).

**First-hour response plan:** be at your keyboard for 60 minutes after posting. Answer every comment, even the pedantic ones, with genuine engagement. HN's ranking heavily weights early comment velocity.

### 4.2 Reddit — r/mcp, r/LocalLLaMA

**Title:**

> Built an MCP proxy that tracks tool-call data flow and blocks cross-tool leaks

**Body:** slightly longer than HN, more casual, include the GIF inline. Emphasize that it's OSS, local, and works with the tools people already use (name-drop Cursor, Claude Desktop).

### 4.3 X / Twitter thread (7 tweets)

1. *"Most MCP security tools are envelope scanners. Sluice is a gate with memory.* 🧵"
2. The problem: secret in `read_file` response is fine. Same secret in later `send_email` is a leak.
3. Diagram or GIF of the block
4. Latency numbers (0.02 ms clean, 0.61 ms with detection)
5. What ships in v0.1: transports, detectors, taint, SQLite audit, CLI
6. What's next: dashboard, Docker, policy presets in v0.2
7. Link + "would love feedback from anyone running MCP in production"

### 4.4 LinkedIn (career surface)

Single post, professional register. Frame around the problem your team was solving. Include screenshot, not GIF (LinkedIn GIFs render badly). Tag it under `#AISafety`, `#MCP`, `#OpenSource`.

---

## 5. Awesome-list PR targets

Batch these on the same day, right after the launch post. Each takes 5 minutes.

| List | Repo | Where to add |
|---|---|---|
| awesome-mcp-servers | `punkpeye/awesome-mcp-servers` | New "Security" or "Proxy" section |
| awesome-mcp | search GitHub for the current canonical one | Usually a "Tooling" or "Security" section |
| awesome-llm-security | `corca-ai/awesome-llm-security` (verify) | Tools / Runtime section |
| awesome-ai-security | search — several exist | Runtime / Guardrails |

**PR template for each:**

```
- [Sluice](https://github.com/<repo>) — Local MCP proxy that tracks data across tool calls
  and blocks cross-tool leaks. Streams `secret`, `PII`, and `tool-poisoning` detection with
  0.02 ms p50 overhead. Apache 2.0.
```

Verify each list's contribution guide before opening the PR — some require alphabetical ordering, some require a specific badge, some run a linter.

---

## 6. First-10-users plan

Cold-ish outreach to people who have publicly shown interest in the MCP space. Aim for warm-tone, no ask beyond "would you try this or trash it."

**Where to find them:**
- Recent commits on `modelcontextprotocol/*` repos
- Authors of MCP servers on npm and PyPI
- Speakers at recent AI-security meetups / conferences (find slide decks)
- People who've tweeted about MCP + security in the last 90 days
- Newsletter authors covering AI safety / MCP

**Template (edit to your voice):**

> Hi <name>,
>
> Saw your work on <specific-thing>. I've been building a small OSS MCP proxy called Sluice that tracks sensitive data across tool calls — the specific problem is that a secret returned from one tool can end up shipped out through another, and none of the existing scanners catch it.
>
> Not asking you to adopt anything. If you have 5 minutes, would love a quick reaction to the README (<URL>) or the 30-second demo. If it's dumb, tell me — I'd rather hear it before more people see it.
>
> Thanks either way.

**Volume:** 10–15 messages over 3 days. Don't blast. Personalize the "saw your work on X" line every single time.

**Track responses in a simple table:** who, when contacted, what channel, response, whether they installed.

---

## 7. Response templates

Pre-written responses to the objections we already know are coming. Edit for context; don't paste literally.

### "How is this different from Invariant's mcp-scan?"

> mcp-scan is largely stateless — it flags a single message. Sluice's differentiator is per-session memory of what data has already been seen inside a session, so a value that entered legitimately in one tool call gets blocked when it tries to leave via another tool. Both projects are valuable; they solve overlapping but distinct problems.

### "Why not use an LLM to detect leaks?"

> Latency and cost. Sluice's clean-path overhead is 0.02 ms — you couldn't notice it if you tried. An LLM in the loop is 100-500 ms per call. For a proxy that sits in every JSON-RPC round-trip, that's not viable. We may add optional LLM-based checks in v0.3 for specific paths (e.g. prompt-injection heuristics), but the fast path stays deterministic.

### "This is just regex, right?"

> The detectors are deterministic patterns + entropy, yes. The interesting part isn't the detectors — it's the taint propagation. A regex tells you "there's a secret here"; Sluice tells you "this specific value came in through `read_file` at 10:04:22 and is now trying to leave via `send_email` at 10:04:31 — block it." That's the wedge.

### "Why not a paid SaaS version?"

> Not planned. Security infra in the JSON-RPC path has to be OSS to be trusted. If a hosted control plane makes sense later, it'd be for team-scale audit review, not for the runtime itself. Runtime stays local, always.

### "Does it work with <specific MCP server>?"

> It works with any MCP server that speaks stdio, HTTP, or streamable HTTP (basically all of them). If you hit issues with a specific server, open an issue with the setup and I'll debug it.

### "Where are the false-positive numbers?"

> Honest answer: I don't have them yet at population scale — you'd be one of the first real users. Detectors are conservative by default (block only on high-confidence patterns, flag on entropy). If you see FPs, that's the most useful bug report you can file.

### "How stable is the API?"

> The config schema, CLI command surface, and detector protocol are stable across v0.x per §7 of the v0.1 architecture doc. Additive changes only until v1.0. Anything under `sluice/` internal modules is not stable yet.

---

## 8. Post-launch check-ins

Every 48 hours during the sprint, spend 15 minutes on:

- **Star count delta.** Vanity, but a leading indicator.
- **Traffic sources.** GitHub Insights → Traffic → Referrers. Where are people coming from?
- **Issue/PR opens.** Any new external contributor? Reply within 24 hours, always.
- **PyPI download count.** `pypistats overall sluice-taint`. Cross-check against star count — installs without stars is a great signal (real users don't star).
- **Search results.** Google "sluice mcp", "mcp security proxy". Are we ranking?
- **Newsletter mentions.** Alert on the project name.

At end of week 1, write a 5-line status update to each other:
- What signal did we get?
- What surprised us?
- Do we adjust positioning?
- Do we double down on any channel that worked?

At end of week 2, decide: continue adoption, start v0.2, or pivot positioning.

---

## 9. What we're not doing during the sprint

Called out to prevent scope creep.

- No new detector types
- No dashboard work
- No v0.2 architecture code (docs OK, code not)
- No refactoring, no "while I'm here" cleanup
- No renaming, no branding overhaul, no logo work
- No paid ads, no sponsorships, no premium listings

Bugs found by real users get fixed immediately. Everything else waits.

---

## 10. Kill criteria

Signals that adoption isn't working and we need to change something before continuing:

- Under 20 stars after both launch posts + all awesome-list PRs merged
- Zero unsolicited issues or DMs
- Bounce rate on repo (measured by star:visit ratio via GitHub insights) is very low
- Reactions to demo GIF are "cool but why would I use this"

If we hit two of these, we do a positioning review before v0.2 build starts. Common outcomes of that review:
1. Rewrite the README pitch (different angle: developer productivity, compliance, audit trail)
2. Target a different community (auditors, SREs, not just AI-safety folks)
3. Build a specific integration nobody asked for that becomes the hook (e.g. Datadog exporter earlier than planned)

Not doing this review is worse than doing it. Silent adoption failure is expensive.

---

## Appendix — checklist for the launch day itself

Morning-of, before anything goes out:

- [ ] Demo GIF renders correctly in README on github.com (not just locally)
- [ ] `pip install sluice-taint` on a clean venv actually works
- [ ] `sluice init && sluice serve` works with only default config
- [ ] `sluice doctor` returns clean on a default config
- [ ] Latency benchmark numbers in README are re-verified
- [ ] LICENSE, SECURITY.md links resolve
- [ ] Repo `About` field is set with the sharp one-line pitch
- [ ] Repo topics set: `mcp`, `model-context-protocol`, `ai-security`, `llm-security`, `proxy`, `claude`, `cursor`
- [ ] You are actually free to respond for the next 4 hours
