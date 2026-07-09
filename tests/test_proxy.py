import pytest

from sluice.config.schema import PolicyConfig, PolicyRule, SluiceConfig
from sluice.detectors.base import ScanContext
from sluice.detectors.secrets import SecretsDetector
from sluice.policy.engine import bootstrap_detectors, evaluate


@pytest.fixture(autouse=True)
def setup():
    bootstrap_detectors()


DEFAULT_CFG = SluiceConfig(
    upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
    policy=PolicyConfig(
        rules=[
            PolicyRule(detector="secrets.high_entropy_string", action="flag"),
            PolicyRule(detector="secrets.*", action="block"),
        ]
    ),
)


def test_aws_key_detected():
    detector = SecretsDetector()
    hits = detector.scan("here is my key AKIAIOSFODNN7EXAMPLE", ScanContext("request", None, None, "test"))
    assert any(h.detector_id == "secrets.aws_access_key" for h in hits)


def test_aws_key_blocked():
    _, violation, _ = evaluate(
        '{"key":"AKIAIOSFODNN7EXAMPLE"}',
        ScanContext("request", "tools/call", "write", "test"),
        DEFAULT_CFG,
    )
    assert violation is not None
    assert violation.action == "block"


def test_clean_text_passes():
    detector = SecretsDetector()
    hits = detector.scan("hello world", ScanContext("request", None, None, "test"))
    assert len(hits) == 0


def test_high_entropy_flagged():
    _, violation, _ = evaluate(
        '{"token":"aB3xK9mPqR7vLnWjYuEiOcTsDfGhZk2"}',
        ScanContext("request", None, None, "test"),
        DEFAULT_CFG,
    )
    assert violation is not None
    assert violation.action == "flag"
