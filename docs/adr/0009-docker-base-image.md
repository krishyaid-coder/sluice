# ADR 0009: `python:3.12-slim` as the Docker base image

Status: Accepted (v0.2 pre-implementation)
Date: 2026-07-11
Deciders: krishna, colleague

## Context

v0.2 ships an official Docker image. See `docs/architecture/v0.2.md` §4.3. The base image choice affects size, security surface, debuggability, and startup time.

Options considered:

- **`python:3.12-slim`** — Debian slim, ~45 MB base, has apt, shell, coreutils
- **`python:3.12-alpine`** — Alpine, ~20 MB base, musl libc, no glibc, apk
- **`gcr.io/distroless/python3-debian12`** — no shell, no package manager, ~50 MB
- **`python:3.12`** — full Debian, ~130 MB

The Sluice image needs to:
- Run `sluice serve` in HTTP mode
- Support `sluice doctor` for troubleshooting (which shells out lightly)
- Let operators exec in for debugging (`docker exec -it ... /bin/sh`)
- Build multi-arch (linux/amd64, linux/arm64) without pain

Sluice has no C extension dependencies, so musl vs glibc doesn't matter for wheels. `aiosqlite`, `httpx`, `fastapi`, `uvicorn`, `typer`, `pydantic`, `pyyaml`, `structlog` all ship pure-Python or manylinux wheels compatible with both.

## Decision

Base image: **`python:3.12-slim`**.

Publish tags `ghcr.io/<repo>/sluice:0.2.0`, `ghcr.io/<repo>/sluice:0.2`, `ghcr.io/<repo>/sluice:latest`.

Multi-arch: `linux/amd64`, `linux/arm64`.

## Consequences

- Image size: ~90 MB final (base + deps + sluice). Larger than Alpine, smaller than full Debian.
- Debuggability: `docker exec -it ... bash` works; users can `apt install curl` for ad-hoc troubleshooting.
- Familiarity: Debian is what most Python devs know. Fewer surprises.
- Not the smallest possible image, but the smallest image where `sluice doctor` runs without pain.
- Alpine's musl would occasionally break Python wheels that assume glibc — not today's problem but a papercut we don't need.
- Distroless is more secure by attack-surface reduction but hostile to debugging. For a proxy that sits in the JSON-RPC path, users being able to exec in and inspect state matters more than a marginal security win.

## Alternatives considered

- **Alpine.** Smaller (~40 MB total). musl libc breaks occasional wheels; hostile to `bash` users; not worth 50 MB savings for a tool that runs as a foreground service.
- **Distroless.** Great for stateless workers behind a service mesh. Wrong for a tool that's meant to be operable by security engineers who want to poke at it.
- **Full `python:3.12`.** Extra 40 MB for build-time deps we don't need at runtime.

## Follow-up

- Dockerfile is a multi-stage build: builder stage installs deps into a venv, runtime stage copies the venv into `python:3.12-slim`
- No root at runtime — `USER sluice` in the runtime stage
- `HEALTHCHECK` runs `sluice doctor` on 30s intervals
- Published via GitHub Actions on `v*` tag push
