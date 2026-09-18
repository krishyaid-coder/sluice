"""Unit tests for PseudonymRegistry and the module-level helpers.

These tests are pure-logic; no pipeline, no config-loader, no I/O. They pin
the invariants the rest of the feature builds on:

- alphabet: 0..25 -> A..Z, 26 -> AA, 27 -> AB, 51 -> AZ, 52 -> BA
- stable within a session: same value always gets the same pseudonym
- fresh across sessions: pseudonym counters restart per session
- type prefix follows detector_id (pii.email -> EMAIL, pii.phone_us -> PHONE)
- reverse lookup returns the original value
- token detection picks up pseudonyms embedded in text
"""

from __future__ import annotations

import pytest

from sluice.config.schema import PseudonymConfig
from sluice.session import pseudonym as ps
from sluice.session.pseudonym import (
    PseudonymRegistry,
    _alphabet_index,
    _type_for_detector,
    find_pseudonym_tokens,
)


@pytest.fixture(autouse=True)
def _reset_store():
    ps.configure(PseudonymConfig(enabled=True))
    yield
    ps.clear()


# ---------------------------------------------------------------------------
# Alphabet index
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "idx,expected",
    [
        (0, "A"),
        (1, "B"),
        (25, "Z"),
        (26, "AA"),
        (27, "AB"),
        (51, "AZ"),
        (52, "BA"),
        (701, "ZZ"),
        (702, "AAA"),
    ],
)
def test_alphabet_index(idx: int, expected: str) -> None:
    assert _alphabet_index(idx) == expected


def test_alphabet_index_negative_rejected() -> None:
    with pytest.raises(ValueError):
        _alphabet_index(-1)


# ---------------------------------------------------------------------------
# Type prefix mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "detector_id,expected",
    [
        ("pii.email", "EMAIL"),
        ("pii.phone_us", "PHONE"),
        ("pii.phone_sg", "PHONE"),
        ("pii.ssn_us", "SSN"),
        ("pii.credit_card", "CARD"),
        ("pii.nric_sg", "NRIC"),
        ("pii.ip_private", "IP"),
    ],
)
def test_type_for_known_detector(detector_id: str, expected: str) -> None:
    assert _type_for_detector(detector_id) == expected


def test_type_for_unknown_pii_detector_derives_prefix() -> None:
    assert _type_for_detector("pii.some_new_thing") == "SOMENEWTHING"


def test_type_for_non_pii_detector_falls_back_to_pii() -> None:
    assert _type_for_detector("secrets.aws_access_key") == "PII"


# ---------------------------------------------------------------------------
# Registry behavior
# ---------------------------------------------------------------------------


def test_stable_within_registry() -> None:
    reg = PseudonymRegistry()
    a1 = reg.assign("jane@corp.com", "pii.email")
    a2 = reg.assign("jane@corp.com", "pii.email")
    assert a1 == a2 == "EMAIL_A"


def test_distinct_values_get_distinct_pseudonyms() -> None:
    reg = PseudonymRegistry()
    a = reg.assign("jane@corp.com", "pii.email")
    b = reg.assign("bob@corp.com", "pii.email")
    c = reg.assign("alice@corp.com", "pii.email")
    assert (a, b, c) == ("EMAIL_A", "EMAIL_B", "EMAIL_C")


def test_type_prefixes_have_independent_counters() -> None:
    reg = PseudonymRegistry()
    reg.assign("jane@corp.com", "pii.email")
    reg.assign("+65 9123 4567", "pii.phone_sg")
    reg.assign("bob@corp.com", "pii.email")
    reg.assign("+1 555 123 4567", "pii.phone_us")
    assert reg.forward["jane@corp.com"] == "EMAIL_A"
    assert reg.forward["bob@corp.com"] == "EMAIL_B"
    assert reg.forward["+65 9123 4567"] == "PHONE_A"
    assert reg.forward["+1 555 123 4567"] == "PHONE_B"


def test_reverse_lookup_returns_value() -> None:
    reg = PseudonymRegistry()
    reg.assign("jane@corp.com", "pii.email")
    assert reg.lookup("EMAIL_A") == "jane@corp.com"
    assert reg.lookup("EMAIL_Z") is None


def test_alphabet_rollover_past_z() -> None:
    reg = PseudonymRegistry()
    # Force 27 assignments so we exercise A..Z, AA.
    for i in range(27):
        reg.assign(f"user{i}@corp.com", "pii.email")
    assert reg.forward["user0@corp.com"] == "EMAIL_A"
    assert reg.forward["user25@corp.com"] == "EMAIL_Z"
    assert reg.forward["user26@corp.com"] == "EMAIL_AA"


def test_empty_value_returns_empty() -> None:
    reg = PseudonymRegistry()
    assert reg.assign("", "pii.email") == ""
    assert reg.is_empty()


def test_mappings_returns_snapshot() -> None:
    reg = PseudonymRegistry()
    reg.assign("jane@corp.com", "pii.email")
    snap = reg.mappings()
    reg.assign("bob@corp.com", "pii.email")
    # Snapshot must not reflect later assignments.
    assert snap == {"jane@corp.com": "EMAIL_A"}


# ---------------------------------------------------------------------------
# Session isolation via the module-level store
# ---------------------------------------------------------------------------


def test_sessions_get_independent_registries() -> None:
    a = ps.assign("sess-1", "jane@corp.com", "pii.email")
    b = ps.assign("sess-2", "jane@corp.com", "pii.email")
    # Same value in two sessions -> two independent (but equal-shape) assignments.
    assert a == "EMAIL_A"
    assert b == "EMAIL_A"
    # Lookups are session-scoped.
    assert ps.lookup("sess-1", "EMAIL_A") == "jane@corp.com"
    assert ps.lookup("sess-2", "EMAIL_A") == "jane@corp.com"


def test_disabled_store_returns_none() -> None:
    ps.configure(PseudonymConfig(enabled=False))
    assert ps.assign("sess-1", "jane@corp.com", "pii.email") is None
    assert ps.lookup("sess-1", "EMAIL_A") is None
    assert ps.mappings_for("sess-1") == {}


def test_clear_session_scoped() -> None:
    ps.assign("sess-1", "jane@corp.com", "pii.email")
    ps.assign("sess-2", "bob@corp.com", "pii.email")
    ps.clear("sess-1")
    assert ps.mappings_for("sess-1") == {}
    assert ps.mappings_for("sess-2") == {"bob@corp.com": "EMAIL_A"}


def test_clear_all_removes_every_session() -> None:
    ps.assign("sess-1", "jane@corp.com", "pii.email")
    ps.assign("sess-2", "bob@corp.com", "pii.email")
    ps.clear()
    assert ps.mappings_for("sess-1") == {}
    assert ps.mappings_for("sess-2") == {}


# ---------------------------------------------------------------------------
# Token detection
# ---------------------------------------------------------------------------


def test_find_pseudonym_tokens_basic() -> None:
    assert find_pseudonym_tokens("Send to EMAIL_A about it") == ["EMAIL_A"]


def test_find_pseudonym_tokens_multiple_distinct() -> None:
    tokens = find_pseudonym_tokens("Email EMAIL_A and PHONE_A about EMAIL_B")
    assert tokens == ["EMAIL_A", "PHONE_A", "EMAIL_B"]


def test_find_pseudonym_tokens_dedup() -> None:
    tokens = find_pseudonym_tokens("Email EMAIL_A, then EMAIL_A again")
    assert tokens == ["EMAIL_A"]


def test_find_pseudonym_tokens_no_false_positives_on_natural_text() -> None:
    # Words like "A_TESTVALUE" that aren't of shape TYPE_LETTERS should not match.
    assert find_pseudonym_tokens("A CONSTANT_VALUE and hello world") == []
    # Lowercase should not match.
    assert find_pseudonym_tokens("email_a is not a pseudonym") == []


def test_find_pseudonym_tokens_in_nested_json_text() -> None:
    text = '{"to": "EMAIL_A", "body": "hello PHONE_A"}'
    assert find_pseudonym_tokens(text) == ["EMAIL_A", "PHONE_A"]


def test_find_pseudonym_tokens_empty_input() -> None:
    assert find_pseudonym_tokens("") == []


def test_find_pseudonym_tokens_ignores_unknown_type_prefixes() -> None:
    # Ordinary code constant — TYPE half is "CONSTANT", not a known pii type.
    # Must not be treated as a pseudonym.
    assert find_pseudonym_tokens("A CONSTANT_VALUE and hello") == []
    assert find_pseudonym_tokens("CODE_A and CACHE_B are not pseudonyms") == []


# ---------------------------------------------------------------------------
# Forward pass via the policy engine
# ---------------------------------------------------------------------------


def _cfg_with_pseudonymize():
    from sluice.config.schema import PolicyConfig, PolicyRule, SluiceConfig

    return SluiceConfig(
        upstreams=[{"name": "demo", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(
            rules=[PolicyRule(detector="pii.*", action="pseudonymize")]
        ),
    )


def test_engine_pseudonymize_replaces_email_with_stable_pseudonym() -> None:
    from sluice.detectors.base import ScanContext
    from sluice.policy.engine import bootstrap_detectors, evaluate

    bootstrap_detectors()
    cfg = _cfg_with_pseudonymize()
    ctx = ScanContext("response", "tools/call", "read_file", "demo", "sess-eng-1")

    body1, violation1, hits1 = evaluate("contact jane@corp.com about it", ctx, cfg)
    assert violation1 is not None
    assert violation1.action == "pseudonymize"
    assert "jane@corp.com" not in body1
    assert "EMAIL_A" in body1

    # Second call in same session -> same pseudonym for the same value.
    body2, _, _ = evaluate("also jane@corp.com should know", ctx, cfg)
    assert "EMAIL_A" in body2

    # A different email -> next letter.
    body3, _, _ = evaluate("cc bob@corp.com too", ctx, cfg)
    assert "EMAIL_B" in body3


def test_engine_pseudonymize_leaves_secrets_redacted_not_pseudonymized() -> None:
    from sluice.detectors.base import ScanContext
    from sluice.policy.engine import bootstrap_detectors, evaluate

    bootstrap_detectors()
    cfg = _cfg_with_pseudonymize()
    ctx = ScanContext("response", "tools/call", "read_file", "demo", "sess-mix-1")

    text = "email jane@corp.com key AKIAIOSFODNN7EXAMPLE"
    body, violation, hits = evaluate(text, ctx, cfg)
    assert violation is not None
    assert violation.action == "pseudonymize"
    # PII becomes a pseudonym.
    assert "EMAIL_A" in body
    assert "jane@corp.com" not in body
    # Secret still gets redacted (safe, no leak).
    assert "AKIAIOSFODNN7EXAMPLE" not in body
    assert "[REDACTED-AWS_ACCESS_KEY]" in body


def test_engine_pseudonymize_disabled_falls_back_to_redact() -> None:
    from sluice.config.schema import PseudonymConfig
    from sluice.detectors.base import ScanContext
    from sluice.policy.engine import bootstrap_detectors, evaluate

    bootstrap_detectors()
    ps.configure(PseudonymConfig(enabled=False))

    cfg = _cfg_with_pseudonymize()
    ctx = ScanContext("response", "tools/call", "read_file", "demo", "sess-off")

    body, violation, _ = evaluate("contact jane@corp.com", ctx, cfg)
    assert violation is not None
    assert violation.action == "pseudonymize"  # action name stays for auditability
    assert "jane@corp.com" not in body
    assert "[REDACTED-EMAIL]" in body  # safe fallback


def test_config_rejects_pseudonymize_for_taint_leak() -> None:
    from sluice.config.schema import PolicyConfig, PolicyRule

    with pytest.raises(ValueError, match="not valid for detector 'taint_leak'"):
        PolicyConfig(rules=[PolicyRule(detector="taint_leak", action="pseudonymize")])
