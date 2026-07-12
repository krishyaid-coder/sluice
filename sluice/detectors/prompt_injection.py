from __future__ import annotations

import re

from sluice.detectors.base import Hit, ScanContext, register

INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (
        "prompt_injection.ignore_instructions",
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        "ignore-previous-instructions phrase",
    ),
    (
        "prompt_injection.system_override",
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(a\s+)?(system|admin|root)",
        "system-role override phrase",
    ),
    (
        "prompt_injection.hidden_markup",
        r"<!--.*?-->",
        "HTML comment in tool output",
    ),
    (
        "prompt_injection.zero_width",
        r"[\u200b-\u200f\ufeff]",
        "zero-width / invisible characters",
    ),
    (
        "prompt_injection.exfil_phrase",
        r"(?i)(send|post|email|upload|forward).{0,40}(all|every|full|secret|password|token)",
        "exfiltration instruction in tool output",
    ),
    (
        "prompt_injection.jailbreak",
        r"(?i)(DAN mode|developer mode|bypass\s+safety|disable\s+guardrails)",
        "jailbreak phrase in tool output",
    ),
]


class PromptInjectionDetector:
    id = "prompt_injection"
    category = "prompt_injection"
    severity = "high"

    def scan(self, text: str, context: ScanContext) -> list[Hit]:
        if context.direction != "response":
            return []
        if context.method not in (None, "tools/call", "resources/read", "prompts/get"):
            return []

        hits: list[Hit] = []
        for detector_id, pattern, label in INJECTION_PATTERNS:
            for match in re.finditer(pattern, text):
                hits.append(
                    Hit(
                        detector_id=detector_id,
                        start=match.start(),
                        end=match.end(),
                        matched=match.group()[:80],
                        label=label,
                        severity="high",
                    )
                )
        return hits


register(PromptInjectionDetector())
