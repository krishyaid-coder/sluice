from __future__ import annotations

import math
import re

from sluice.detectors.base import Hit, ScanContext, register

PATTERNS: dict[str, str] = {
    "secrets.aws_access_key": r"AKIA[0-9A-Z]{16}",
    "secrets.github_token": r"ghp_[a-zA-Z0-9]{36}",
    "secrets.openai_key": r"sk-[a-zA-Z0-9]{48}",
    "secrets.anthropic_key": r"sk-ant-[a-zA-Z0-9\-]{90,}",
    "secrets.jwt": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "secrets.private_key_pem": r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    "secrets.stripe_live": r"sk_live_[0-9a-zA-Z]{24}",
    "secrets.gcp_api_key": r"AIza[0-9A-Za-z\-_]{35}",
}

SEVERITY: dict[str, str] = {
    "secrets.aws_access_key": "critical",
    "secrets.github_token": "critical",
    "secrets.openai_key": "critical",
    "secrets.anthropic_key": "critical",
    "secrets.jwt": "medium",
    "secrets.private_key_pem": "critical",
    "secrets.stripe_live": "critical",
    "secrets.gcp_api_key": "critical",
    "secrets.high_entropy_string": "low",
}

ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_LEN = 20


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _high_entropy_tokens(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for token in re.split(r"[\s,;\"']+", text):
        if len(token) >= MIN_ENTROPY_LEN and _shannon_entropy(token) >= ENTROPY_THRESHOLD:
            start = text.find(token)
            if start >= 0:
                hits.append(
                    Hit(
                        detector_id="secrets.high_entropy_string",
                        start=start,
                        end=start + len(token),
                        matched=token,
                        label="high-entropy string",
                        severity="low",
                    )
                )
    return hits


class SecretsDetector:
    id = "secrets"
    category = "secrets"
    severity = "high"

    def scan(self, text: str, context: ScanContext) -> list[Hit]:
        hits: list[Hit] = []
        for detector_id, pattern in PATTERNS.items():
            for match in re.finditer(pattern, text):
                hits.append(
                    Hit(
                        detector_id=detector_id,
                        start=match.start(),
                        end=match.end(),
                        matched=match.group(),
                        label=detector_id.split(".", 1)[-1].replace("_", " "),
                        severity=SEVERITY.get(detector_id, "high"),  # type: ignore[arg-type]
                    )
                )
        if not hits:
            hits.extend(_high_entropy_tokens(text))
        return hits


def redact(text: str, hits: list[Hit] | None = None) -> tuple[str, list[Hit]]:
    if hits is None:
        hits = SecretsDetector().scan(text, ScanContext("request", None, None, ""))
    redacted = text
    for h in sorted(hits, key=lambda x: x.start, reverse=True):
        tag = h.detector_id.split(".")[-1].upper()
        redacted = redacted[: h.start] + f"[REDACTED-{tag}]" + redacted[h.end :]
    return redacted, hits


register(SecretsDetector())
