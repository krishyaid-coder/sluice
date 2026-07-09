from sluice.detectors.base import ScanContext
from sluice.detectors.pii import PIIDetector, redact


def test_email_detected():
    hits = PIIDetector().scan("contact me at user@example.com please", ScanContext("request", None, None, "test"))
    assert any(h.detector_id == "pii.email" for h in hits)


def test_sg_phone_detected():
    hits = PIIDetector().scan("call me at +65 9123 4567", ScanContext("request", None, None, "test"))
    assert any(h.detector_id == "pii.phone_sg" for h in hits)


def test_nric_detected():
    hits = PIIDetector().scan("my NRIC is S1234567D", ScanContext("request", None, None, "test"))
    assert any(h.detector_id == "pii.nric_sg" for h in hits)


def test_credit_card_detected():
    hits = PIIDetector().scan("card: 4111 1111 1111 1111", ScanContext("request", None, None, "test"))
    assert any(h.detector_id == "pii.credit_card" for h in hits)


def test_redact_email():
    redacted, hits = redact("email me at foo@bar.com")
    assert "foo@bar.com" not in redacted
    assert "[REDACTED-EMAIL]" in redacted


def test_clean_text_no_pii():
    hits = PIIDetector().scan("the weather in Singapore is hot today", ScanContext("request", None, None, "test"))
    assert len(hits) == 0
