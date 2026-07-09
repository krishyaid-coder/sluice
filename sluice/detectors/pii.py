from __future__ import annotations

import re

from sluice.detectors.base import Hit, ScanContext, register

PII_PATTERNS: dict[str, str] = {
    "pii.email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "pii.phone_us": r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "pii.phone_sg": r"\b(\+65[-.\s]?)?[689]\d{3}[-.\s]?\d{4}\b",
    "pii.nric_sg": r"\b[STFGM]\d{7}[A-Z]\b",
    "pii.passport": r"\b[A-Z]{1,2}\d{6,9}\b",
    "pii.credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "pii.ssn_us": r"\b\d{3}-\d{2}-\d{4}\b",
    "pii.ip_private": r"\b(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
}


class PIIDetector:
    id = "pii"
    category = "pii"
    severity = "medium"

    def scan(self, text: str, context: ScanContext) -> list[Hit]:
        hits: list[Hit] = []
        for detector_id, pattern in PII_PATTERNS.items():
            for match in re.finditer(pattern, text):
                hits.append(
                    Hit(
                        detector_id=detector_id,
                        start=match.start(),
                        end=match.end(),
                        matched=match.group(),
                        label=detector_id.split(".", 1)[-1].replace("_", " "),
                        severity="high" if "ssn" in detector_id or "credit" in detector_id else "medium",
                    )
                )
        return hits


def redact(text: str, hits: list[Hit] | None = None) -> tuple[str, list[Hit]]:
    if hits is None:
        hits = PIIDetector().scan(text, ScanContext("request", None, None, ""))
    redacted = text
    for h in sorted(hits, key=lambda x: x.start, reverse=True):
        tag = h.detector_id.split(".")[-1].upper()
        redacted = redacted[: h.start] + f"[REDACTED-{tag}]" + redacted[h.end :]
    return redacted, hits


register(PIIDetector())
