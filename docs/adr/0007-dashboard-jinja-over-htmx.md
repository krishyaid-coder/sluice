# ADR 0007: Jinja + vanilla CSS for the v0.2 dashboard

Status: Accepted (v0.2 pre-implementation)
Date: 2026-07-11
Deciders: krishna, colleague

## Context

v0.2 ships a read-only HTML dashboard at `/_sluice/` for viewing recent audit events, active sessions, and taint marks. See `docs/architecture/v0.2.md` §4.2.

The dashboard needs to:
- Render from server-side data (SQLite audit rows)
- Load fast on modern browsers (< 150 ms p95 for the overview page)
- Not require a build step (`npm install`, webpack, vite) in the Sluice repo
- Not require a JS runtime for basic functionality
- Not become a security surface — no user-generated HTML, no untrusted scripts

The natural stack options:

1. **Jinja + vanilla CSS + progressive HTML** — server-rendered, form-based interactions, `<details>`/`<dialog>` for interactivity
2. **Jinja + HTMX** — server-rendered, HTMX for partial page updates
3. **A JS SPA (React, Svelte, etc.)** — client-heavy, requires a build pipeline
4. **A dedicated Python dashboard framework (Streamlit, Dash)** — heavy runtime, bad fit for embedding under `/_sluice/`

## Decision

Ship the v0.2 dashboard with **Jinja templates + vanilla CSS + progressive HTML**. No JavaScript framework, no HTMX. Filters and pagination happen via plain HTML forms (`<form method="get">`).

If a specific page hits a real UX friction point — most likely the events list needing live updates without a full page reload — we adopt **HTMX** narrowly for that page. Not before.

## Consequences

- Zero build step. `sluice serve` renders the dashboard directly from `sluice/dashboard/templates/`.
- Contributor bar is low: HTML + CSS + Jinja is the least-common-denominator web skill set.
- The dashboard is 100% functional with JavaScript disabled, which happens to also make it screen-reader-friendly for free.
- No live updates — users reload to see new events. Acceptable in v0.2 given the target use case (post-hoc review, not live monitoring).
- Adding HTMX later is a two-line change (one `<script>` tag inline in the base template, plus attributes on the target element). We don't commit to it now.
- No design system, no component library. Aesthetics are utilitarian. If we want polish in v0.3, that's a separate ADR.

## Alternatives considered

- **HTMX from day one.** Enables partial page updates and inline filtering nicely. Rejected because it adds a dependency (even if tiny) and a mental model, both for problems we don't have yet.
- **JS SPA.** Fastest interactivity, worst everything else — build step, dep tree, bundle size, security surface. Not worth it for a read-only ops tool.
- **Streamlit / Dash.** Fine as separate apps; wrong shape for a `/_sluice/` sub-app on the same port.
