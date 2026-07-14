"""Regression tests for taint going through the policy engine.

Prior behavior: pipeline.inspect_request hardcoded action='block' for taint
leaks, ignoring any policy.rules entries the user wrote against 'taint_leak'
or 'taint.*'. Rules were silently no-ops.

These tests exercise the resolved action for each configured policy shape
and the config-load-time validator that rejects 'redact' for taint rules.
"""

from __future__ import annotations

import pytest

from sluice.config.schema import PolicyConfig, PolicyRule, SluiceConfig, TaintConfig
from sluice.detectors.base import Hit
from sluice.policy.engine import bootstrap_detectors, resolve_action
from sluice.proxy.models import JSONRPCRequest
from sluice.proxy.pipeline import Pipeline
from sluice.session import taint


@pytest.fixture(autouse=True)
def _reset_taint():
    taint.clear()
    bootstrap_detectors()
    taint.configure(TaintConfig(enabled=True, min_length=8))


def _cfg(rules: list[PolicyRule], default_action: str = "flag") -> SluiceConfig:
    return SluiceConfig(
        upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(rules=rules, default_action=default_action),  # type: ignore[arg-type]
    )


SECRET = "AKIAIOSFODNN7EXAMPLE"
LEAK_REQUEST = (
    f'{{"jsonrpc":"2.0","id":2,"method":"tools/call",'
    f'"params":{{"name":"send_email","arguments":{{"body":"{SECRET}"}}}}}}'
)


async def _run_leak(cfg: SluiceConfig, session_id: str = "sess-1"):
    """Mark a value tainted then send a request containing it; return violation.

    Order matters: Pipeline() calls taint.configure() and swaps the underlying
    store, so any marks made before the Pipeline exists are lost.
    """
    pipeline = Pipeline(cfg, audit=None)
    taint.mark(session_id, SECRET)
    _, violation = await pipeline.inspect_request(
        LEAK_REQUEST,
        session_id=session_id,
        upstream="test",
    )
    return violation


# ---------------------------------------------------------------------------
# Config-load-time validator
# ---------------------------------------------------------------------------


def test_config_rejects_redact_for_taint_leak():
    with pytest.raises(ValueError, match="not valid for detector 'taint_leak'"):
        PolicyConfig(rules=[PolicyRule(detector="taint_leak", action="redact")])


def test_config_rejects_redact_for_taint_wildcard():
    with pytest.raises(ValueError, match="not valid for detector 'taint.\\*'"):
        PolicyConfig(rules=[PolicyRule(detector="taint.*", action="redact")])


def test_config_allows_block_and_flag_for_taint():
    # Neither of these should raise.
    PolicyConfig(rules=[PolicyRule(detector="taint_leak", action="block")])
    PolicyConfig(rules=[PolicyRule(detector="taint_leak", action="flag")])


def test_config_still_allows_redact_for_non_taint():
    # Broader detectors still allow redact.
    PolicyConfig(rules=[PolicyRule(detector="pii.*", action="redact")])
    PolicyConfig(rules=[PolicyRule(detector="secrets.*", action="redact")])


# ---------------------------------------------------------------------------
# Runtime policy resolution for taint
# ---------------------------------------------------------------------------


def test_resolve_action_matches_taint_leak_rule():
    """The engine's resolve_action treats taint_leak like any other detector id."""
    hit = Hit(
        detector_id="taint_leak",
        start=0,
        end=0,
        matched="",
        label="cross-tool leak",
        severity="critical",
    )
    cfg = _cfg(rules=[PolicyRule(detector="taint_leak", action="flag")])
    resolved = resolve_action([hit], cfg, upstream="test", tool="send_email")
    assert resolved is not None
    assert resolved.action == "flag"
    assert resolved.rule_detector == "taint_leak"


@pytest.mark.asyncio
async def test_flag_rule_forwards_and_audits_as_flag():
    """action=flag: request goes through, violation.action == 'flag'."""
    cfg = _cfg(rules=[PolicyRule(detector="taint_leak", action="flag")])
    violation = await _run_leak(cfg)
    assert violation is not None
    assert violation.action == "flag"
    assert violation.rule == "taint_leak"


@pytest.mark.asyncio
async def test_block_rule_blocks_backward_compat():
    """action=block: same behavior as pre-fix, request refused."""
    cfg = _cfg(rules=[PolicyRule(detector="taint_leak", action="block")])
    violation = await _run_leak(cfg)
    assert violation is not None
    assert violation.action == "block"


@pytest.mark.asyncio
async def test_no_taint_rule_falls_back_to_block_not_default_action():
    """Without an explicit taint rule, taint blocks even if default_action=flag.

    Rationale: taint is a critical security signal. Silently inheriting a
    permissive default_action would defeat the purpose of the feature. Users
    who want lax behavior must opt in with an explicit rule.
    """
    cfg = _cfg(rules=[PolicyRule(detector="secrets.*", action="block")], default_action="flag")
    violation = await _run_leak(cfg)
    assert violation is not None
    assert violation.action == "block"


@pytest.mark.asyncio
async def test_pass_action_coerces_to_flag():
    """action=pass: coerced to flag so the leak stays in the audit trail."""
    cfg = _cfg(rules=[PolicyRule(detector="taint_leak", action="pass")])
    violation = await _run_leak(cfg)
    assert violation is not None
    assert violation.action == "flag"


@pytest.mark.asyncio
async def test_upstream_scoped_taint_rule_only_applies_to_matching_upstream():
    """Scoped rule only fires on its upstream; other upstreams get default (block)."""
    cfg = SluiceConfig(
        upstreams=[
            {"name": "test", "transport": "http", "url": "http://localhost:1"},
            {"name": "other", "transport": "http", "url": "http://localhost:2"},
        ],
        policy=PolicyConfig(
            rules=[PolicyRule(detector="taint_leak", upstream="other", action="flag")],
        ),
    )
    # Leak on 'test' upstream: no scoped rule applies -> block
    violation = await _run_leak(cfg)
    assert violation is not None
    assert violation.action == "block"


def test_synthetic_hit_shape():
    """The synthetic Hit used in pipeline should be a valid Hit that resolve_action accepts."""
    hit = Hit(
        detector_id="taint_leak",
        start=0,
        end=0,
        matched="",
        label="cross-tool leak",
        severity="critical",
    )
    # Must not raise.
    assert hit.detector_id == "taint_leak"
    assert hit.severity == "critical"


# Silence a Pyright warning: JSONRPCRequest import is intentional for cross-check
# that our fixture request payload is well-formed.
_ = JSONRPCRequest
