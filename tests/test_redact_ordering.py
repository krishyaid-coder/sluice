"""Regression tests for the redact-offset-corruption bug.

Prior behavior: engine.evaluate() called secrets.redact() then pii.redact()
with pii_hits whose offsets were computed against the pre-secret-redact body.
That meant if a secret's offset was lower than a pii match's, the pii
redaction landed at the wrong position — leaving actual pii visible while
mangling unrelated bytes.

These tests exercise the interleaving cases and assert both categories are
cleanly removed with nothing left over.
"""

from __future__ import annotations

from sluice.config.schema import PolicyConfig, PolicyRule, SluiceConfig
from sluice.detectors.base import ScanContext
from sluice.policy.engine import bootstrap_detectors, evaluate

CTX = ScanContext("request", None, None, "test")


def _cfg() -> SluiceConfig:
    return SluiceConfig(
        upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(
            rules=[
                PolicyRule(detector="secrets.*", action="redact"),
                PolicyRule(detector="pii.*", action="redact"),
            ]
        ),
    )


def test_secret_before_pii_both_redacted_cleanly():
    """Secret at a lower offset than an email: both get redacted, email fully gone."""
    bootstrap_detectors()
    raw = "api key: AKIAIOSFODNN7EXAMPLE user: jane@corp.com"
    body, violation, _ = evaluate(raw, CTX, _cfg())

    assert violation is not None
    assert violation.action == "redact"
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "jane@corp.com" not in body
    assert "jane@" not in body  # no partial leak
    assert "[REDACTED-AWS_ACCESS_KEY]" in body
    assert "[REDACTED-EMAIL]" in body


def test_pii_before_secret_both_redacted_cleanly():
    """Reverse order: email first, secret after. Both go, nothing partial."""
    bootstrap_detectors()
    raw = "user: jane@corp.com api key: AKIAIOSFODNN7EXAMPLE"
    body, violation, _ = evaluate(raw, CTX, _cfg())

    assert violation is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "jane@corp.com" not in body
    assert "corp.com" not in body
    assert "[REDACTED-EMAIL]" in body
    assert "[REDACTED-AWS_ACCESS_KEY]" in body


def test_multiple_interleaved_hits():
    """Two secrets and two pii values interleaved. All four go, none partial."""
    bootstrap_detectors()
    raw = (
        "alice@corp.com "
        "AKIAIOSFODNN7EXAMPLE "
        "bob@corp.com "
        "AKIA1234567890ABCDEF"
    )
    body, violation, _ = evaluate(raw, CTX, _cfg())

    assert violation is not None
    assert "alice@corp.com" not in body
    assert "bob@corp.com" not in body
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "AKIA1234567890ABCDEF" not in body
    # No partial leaks of the local-part of either email
    assert "alice@" not in body
    assert "bob@" not in body
    assert body.count("[REDACTED-EMAIL]") == 2
    assert body.count("[REDACTED-AWS_ACCESS_KEY]") == 2


def test_surrounding_text_untouched():
    """Text between and around redactions stays exactly as-is."""
    bootstrap_detectors()
    raw = "PREFIX AKIAIOSFODNN7EXAMPLE MIDDLE jane@corp.com SUFFIX"
    body, violation, _ = evaluate(raw, CTX, _cfg())

    assert violation is not None
    assert body.startswith("PREFIX ")
    assert " MIDDLE " in body
    assert body.endswith(" SUFFIX")
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "jane@corp.com" not in body


def test_pii_only_still_works():
    """Regression guard: single-category redact still works after the refactor."""
    bootstrap_detectors()
    cfg = SluiceConfig(
        upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(rules=[PolicyRule(detector="pii.*", action="redact")]),
    )
    raw = "email: alice@corp.com and bob@corp.com"
    body, violation, _ = evaluate(raw, CTX, cfg)

    assert violation is not None
    assert "alice@corp.com" not in body
    assert "bob@corp.com" not in body
    assert body.count("[REDACTED-EMAIL]") == 2


def test_secrets_only_still_works():
    """Regression guard: single-category redact still works after the refactor."""
    bootstrap_detectors()
    cfg = SluiceConfig(
        upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(rules=[PolicyRule(detector="secrets.*", action="redact")]),
    )
    raw = "key1=AKIAIOSFODNN7EXAMPLE key2=AKIA1234567890ABCDEF"
    body, violation, _ = evaluate(raw, CTX, cfg)

    assert violation is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "AKIA1234567890ABCDEF" not in body
    assert body.count("[REDACTED-AWS_ACCESS_KEY]") == 2
