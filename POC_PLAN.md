# Sluice — POC Plan

Living roadmap for Sluice. Last updated after **v0.3.0** shipped (PyPI: `sluice-taint`).

---

## 1. Vision

Sluice is a local-first, open-source flow-control proxy for the Model Context Protocol. It sits between an AI agent (Claude Desktop, Cursor, Cline, custom) and one or more MCP servers, inspecting every JSON-RPC message in both directions for credential leaks, PII, policy violations, and cross-tool data-flow risks.

**One-line pitch:** *The MCP gate that remembers what your agent already saw.*

**Non-goals (explicit):**
- Not a SaaS. No telemetry, no phone-home, no hosted plane.
- Not an LLM-based scanner. Detectors are deterministic and fast.
- Not a replacement for IAM or network policy — it's a content-level inspector.

---

## 2. Why this is worth open-sourcing

### Our wedge
1. **Session taint propagation** — track secrets/PII across tool calls. Headline feature.
2. **Local-first, zero telemetry** — for security-conscious devs and regulated orgs.
3. **Drop-in for Claude Desktop / Cursor in under 60 seconds** — two-line config change.

---

## 3. Current state (v0.3.0)

### Shipped

| Area | Status |
|---|---|
| CLI (`init`, `serve`, `stdio`, `logs`, `doctor`, `version`, `presets`) | Done |
| stdio + HTTP + streamable HTTP (SSE reconnect) | Done |
| Detectors: secrets, PII, tool_poisoning, prompt_injection | Done |
| Session taint + taint v2 provenance / propagation graph | Done |
| Policy presets (filesystem, github, slack, postgres, brave-search) | Done |
| SQLite audit + optional OTel export | Done |
| HTML dashboard at `/_sluice/` | Done |
| Docker image (`Dockerfile`, `docker-compose.yml`) | Done |
| CI: pytest + ruff + bench + integration tests | Done |
| LICENSE (Apache 2.0), SECURITY.md, CONTRIBUTING.md | Done |
| Latency benchmark in CI; numbers in README | Done |
| `${VAR}` env expansion, legacy `config.yaml.upgraded` migration | Done |
| PyPI: `pip install sluice-taint` (v0.3.0) | Done |
| E2E guide: [docs/guide.md](docs/guide.md) | Done |
| Detector catalogue: [docs/detectors.md](docs/detectors.md) | Done |

### Still open

| Item | Notes |
|---|---|
| 30-second demo GIF in README | Script + recording guide exist; asset not committed yet |
| External validation | Stars, newsletter mention, unsolicited issue/PR — track manually |
| GHCR image publish | Workflow added; first publish on next tag or manual trigger |
| Real `npx` filesystem MCP in CI | Optional integration test; mock server covers core paths today |

---

## 4. Roadmap (completed)

### Phase 1 — v0.1.0 public release

- [x] Multi-upstream config
- [x] Tool-poisoning scanner on `tools/list`
- [x] SQLite audit + `sluice logs`
- [x] Per-tool policy rules
- [x] Session-scoped taint
- [x] Streamable HTTP transport (SSE + `Last-Event-Id` reconnect)
- [x] Latency benchmark + README numbers
- [x] GitHub Actions (pytest + ruff + bench)
- [x] LICENSE, SECURITY.md
- [x] `${VAR}` expansion, config migration
- [x] PyPI (`sluice-taint`)
- [ ] Demo GIF (recording guide at [docs/demo-recording.md](docs/demo-recording.md))

### Phase 2 — v0.2.0 credibility

- [x] Policy presets (top 5 MCP servers)
- [x] Docker image + quickstart
- [x] Read-only HTML dashboard
- [x] Integration tests in CI (mock MCP server)
- [x] CONTRIBUTING.md + detector docs

### Phase 3 — v0.3.0 differentiator

- [x] Taint v2 — JSON-path provenance, propagation graph in audit
- [x] Prompt-injection heuristics on tool responses
- [x] OpenTelemetry exporter (`pip install sluice-taint[otel]`)
- [x] Plugin API docs (entry points + `docs/detectors.md`)

---

## 5. Success metrics

| Metric | Target | Status |
|---|---|---|
| Install to first block | Under 5 minutes | Met (see docs/guide.md) |
| p95 overhead (no match) | Under 5 ms | Met (0.02 ms clean) |
| p95 overhead (with redaction) | Under 20 ms | Met (0.85 ms secret) |
| Week 1 external signal | 100+ stars / mention / unsolicited PR | Open |
| Demo GIF shared | At least once on social | Open |

---

## 6. What we are NOT shipping

- Hosted / SaaS version
- LLM-based scanning
- Replacement for IAM, VPN, or network firewalls
- Full field-level data-flow analysis (beyond best-effort JSON paths)
- Web dashboard SPA

---

## 7. References

- User guide: [docs/guide.md](docs/guide.md)
- Architecture: [Architecture.md](Architecture.md)
- MCP spec: https://modelcontextprotocol.io
- PyPI: https://pypi.org/project/sluice-taint/
