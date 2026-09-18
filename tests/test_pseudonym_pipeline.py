"""End-to-end pipeline tests for the pseudonymize round-trip.

Covers:
- Forward: tool response with PII -> AI sees pseudonym
- Reverse: AI writes pseudonym in outbound tool call -> tool sees real value
- Fail-closed: unknown pseudonym in outbound -> block
- Direction guard: pseudonymize action on request direction is coerced to flag
- Taint interaction: reversed values do not trigger taint blocks
- Mixed messages: PII gets pseudonymized, secrets still get redacted
"""

from __future__ import annotations

import json

import pytest

from sluice.config.schema import (
    PolicyConfig,
    PolicyRule,
    PseudonymConfig,
    SluiceConfig,
    TaintConfig,
)
from sluice.proxy.pipeline import Pipeline
from sluice.session import pseudonym as ps
from sluice.session import taint


@pytest.fixture(autouse=True)
def _reset_stores():
    taint.clear()
    ps.clear()
    yield
    taint.clear()
    ps.clear()


def _cfg(rules: list[PolicyRule] | None = None) -> SluiceConfig:
    if rules is None:
        rules = [PolicyRule(detector="pii.*", action="pseudonymize")]
    return SluiceConfig(
        upstreams=[{"name": "demo", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(rules=rules),
        pseudonym=PseudonymConfig(enabled=True, fail_closed_on_reverse=True),
        taint=TaintConfig(enabled=True, min_length=8),
    )


# ---------------------------------------------------------------------------
# Forward direction (tool response -> client)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_response_pii_gets_pseudonymized() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    raw_response = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"contact": "jane@corp.com", "backup": "bob@corp.com"},
        }
    )
    body, violation = await pipe.inspect_response(
        raw_response, session_id="sess-fwd", upstream="demo", method="tools/call"
    )
    assert violation is not None
    assert violation.action == "pseudonymize"
    assert "jane@corp.com" not in body
    assert "bob@corp.com" not in body
    assert "EMAIL_A" in body
    assert "EMAIL_B" in body


@pytest.mark.asyncio
async def test_response_same_value_gets_stable_pseudonym() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    r1 = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"who": "jane@corp.com"}})
    r2 = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"who": "jane@corp.com"}})

    body1, _ = await pipe.inspect_response(
        r1, session_id="sess-stable", upstream="demo", method="tools/call"
    )
    body2, _ = await pipe.inspect_response(
        r2, session_id="sess-stable", upstream="demo", method="tools/call"
    )
    assert "EMAIL_A" in body1
    assert "EMAIL_A" in body2  # same value, same session -> same pseudonym


# ---------------------------------------------------------------------------
# Reverse direction (client -> tool)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reverse_pass_restores_real_value_before_forwarding() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    # Step 1: seed the registry via a response.
    seed = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"who": "jane@corp.com"}})
    body_out, _ = await pipe.inspect_response(
        seed, session_id="sess-rev", upstream="demo", method="tools/call"
    )
    assert "EMAIL_A" in body_out

    # Step 2: AI issues an outbound call using the pseudonym.
    outbound = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "EMAIL_A"}},
        }
    )
    forwarded, violation = await pipe.inspect_request(
        outbound, session_id="sess-rev", upstream="demo"
    )
    # The tool server sees the real email address, not the pseudonym.
    assert "jane@corp.com" in forwarded
    assert "EMAIL_A" not in forwarded
    # This is a legitimate substitution — no block.
    assert violation is None or violation.action != "block"


@pytest.mark.asyncio
async def test_reverse_pass_fails_closed_on_unknown_pseudonym() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    # No response ever seeded EMAIL_Z into this session.
    outbound = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "EMAIL_Z"}},
        }
    )
    forwarded, violation = await pipe.inspect_request(
        outbound, session_id="sess-fail", upstream="demo"
    )
    assert violation is not None
    assert violation.action == "block"
    assert violation.rule == "pseudonym_unknown"
    # Message is not modified when blocked.
    assert "EMAIL_Z" in forwarded


@pytest.mark.asyncio
async def test_reverse_pass_allowed_when_fail_closed_disabled() -> None:
    cfg = _cfg()
    cfg.pseudonym = PseudonymConfig(enabled=True, fail_closed_on_reverse=False)
    pipe = Pipeline(cfg, audit=None)

    outbound = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "EMAIL_Z"}},
        }
    )
    forwarded, violation = await pipe.inspect_request(
        outbound, session_id="sess-lax", upstream="demo"
    )
    # No block; the unknown pseudonym passes through unchanged.
    assert violation is None or violation.action != "block"
    assert "EMAIL_Z" in forwarded


# ---------------------------------------------------------------------------
# Direction guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pseudonymize_on_request_direction_coerces_to_flag() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    # AI issues a request with raw PII directly (no pseudonym). Rule says
    # pseudonymize but that's response-only; on request it should coerce to flag.
    outbound = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "jane@corp.com"}},
        }
    )
    forwarded, violation = await pipe.inspect_request(
        outbound, session_id="sess-dir", upstream="demo"
    )
    assert violation is not None
    assert violation.action == "flag"
    # Real value passes through — user wanted this to reach the tool.
    assert "jane@corp.com" in forwarded


# ---------------------------------------------------------------------------
# Taint interaction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reversed_pseudonym_is_exempt_from_taint_block() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    # Step 1: response with PII pseudonymized. Value also gets marked in taint
    # (redact/flag/pass responses mark taint per pipeline.inspect_response).
    seed = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"who": "jane@corp.com"}})
    await pipe.inspect_response(
        seed, session_id="sess-taint", upstream="demo", method="tools/call"
    )
    # Manually mark the value tainted too (belt and suspenders — the response
    # side may or may not mark depending on action semantics).
    taint.mark("sess-taint", "jane@corp.com")

    # Step 2: AI writes the pseudonym in an outbound call.
    outbound = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "EMAIL_A"}},
        }
    )
    forwarded, violation = await pipe.inspect_request(
        outbound, session_id="sess-taint", upstream="demo"
    )
    # The reverse pass substituted jane@corp.com for EMAIL_A. Taint check
    # was skipped because a substitution happened. Real value reaches the
    # tool without a taint_leak block.
    assert "jane@corp.com" in forwarded
    assert violation is None or violation.action == "flag"


@pytest.mark.asyncio
async def test_taint_still_fires_when_ai_writes_raw_value_directly() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    # Seed the taint store directly (simulating value having entered session
    # via some earlier read).
    taint.mark("sess-direct", "jane@corp.com")

    # AI writes the raw value directly in outbound (no pseudonym).
    outbound = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"body": "jane@corp.com"}},
        }
    )
    forwarded, violation = await pipe.inspect_request(
        outbound, session_id="sess-direct", upstream="demo"
    )
    # No pseudonym substitution happened -> taint check runs -> block.
    assert violation is not None
    assert violation.action == "block"
    assert violation.rule == "taint_leak"


# ---------------------------------------------------------------------------
# Mixed messages (PII + secret)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mixed_pii_and_secret_response_pseudonymizes_pii_redacts_secret() -> None:
    cfg = _cfg()
    pipe = Pipeline(cfg, audit=None)

    # Response with both a PII value and a secret.
    raw = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"email": "jane@corp.com", "aws": "AKIAIOSFODNN7EXAMPLE"},
        }
    )
    body, violation = await pipe.inspect_response(
        raw, session_id="sess-mix", upstream="demo", method="tools/call"
    )
    assert violation is not None
    assert violation.action == "pseudonymize"
    # PII pseudonymized.
    assert "jane@corp.com" not in body
    assert "EMAIL_A" in body
    # Secret redacted (safe, no leak).
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "[REDACTED-AWS_ACCESS_KEY]" in body
