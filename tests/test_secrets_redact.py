from sluice.config.schema import PolicyConfig, PolicyRule, SluiceConfig
from sluice.detectors.base import ScanContext
from sluice.detectors.secrets import redact
from sluice.policy.engine import bootstrap_detectors, evaluate


def test_redact_aws_key():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    redacted, detections = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED-AWS_ACCESS_KEY]" in redacted
    assert len(detections) == 1


def test_policy_redact_secrets():
    bootstrap_detectors()
    cfg = SluiceConfig(
        upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(rules=[PolicyRule(detector="secrets.aws_access_key", action="redact")]),
    )
    raw = '{"content":"AKIAIOSFODNN7EXAMPLE"}'
    body, violation, _ = evaluate(raw, ScanContext("request", None, None, "test"), cfg)
    assert violation is not None
    assert violation.action == "redact"
    assert "AKIAIOSFODNN7EXAMPLE" not in body
