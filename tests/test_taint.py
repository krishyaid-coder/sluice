import pytest

from sluice.config.schema import PolicyConfig, PolicyRule, SluiceConfig, TaintConfig
from sluice.detectors.base import ScanContext
from sluice.policy.engine import bootstrap_detectors, evaluate
from sluice.session import taint


@pytest.fixture(autouse=True)
def setup_taint():
    taint.clear()
    bootstrap_detectors()
    taint.configure(TaintConfig(enabled=True, min_length=8))


DEFAULT_CFG = SluiceConfig(
    upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
    policy=PolicyConfig(rules=[PolicyRule(detector="secrets.*", action="block")]),
)


def test_taint_blocks_reuse():
    secret = "AKIAIOSFODNN7EXAMPLE"
    response = f'{{"jsonrpc":"2.0","id":1,"result":{{"content":"key={secret}"}}}}'

    _, _, hits = evaluate(
        response,
        ScanContext("response", "tools/call", "read", "test", "sess-1"),
        DEFAULT_CFG,
    )
    taint.mark_from_hits("sess-1", [h.matched for h in hits])

    request = (
        f'{{"jsonrpc":"2.0","id":2,"method":"tools/call",'
        f'"params":{{"arguments":{{"body":"{secret}"}}}}}}'
    )
    leak = taint.check("sess-1", request)
    assert leak == secret


def test_taint_disabled_allows_reuse():
    taint.clear()
    taint.configure(TaintConfig(enabled=False))
    secret = "supersecretvalue12345"
    taint.mark("sess-1", secret)
    assert taint.check("sess-1", f'{{"text":"{secret}"}}') is None
