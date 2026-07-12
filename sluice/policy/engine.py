from __future__ import annotations

import fnmatch
from dataclasses import dataclass

import structlog

from sluice.config.schema import SluiceConfig
from sluice.detectors import pii as pii_detector
from sluice.detectors import (
    prompt_injection,  # noqa: F401 — register detector
    tool_poisoning,  # noqa: F401 — register detector
)
from sluice.detectors import secrets as secrets_detector
from sluice.detectors.base import (
    Hit,
    ScanContext,
    get_registry,
    load_entry_point_detectors,
    scan_all,
)
from sluice.proxy.models import PolicyViolation

log = structlog.get_logger()


@dataclass(frozen=True)
class ResolvedAction:
    action: str
    rule_detector: str
    preset_source: str | None
    hits: list[Hit]


def _enabled_categories(cfg: SluiceConfig) -> set[str]:
    enabled: set[str] = set()
    if cfg.detectors.secrets.enabled:
        enabled.add("secrets")
    if cfg.detectors.pii.enabled:
        enabled.add("pii")
    if cfg.detectors.tool_poisoning.enabled:
        enabled.add("tool_poisoning")
    if cfg.detectors.prompt_injection.enabled:
        enabled.add("prompt_injection")
    return enabled


def _filter_hits(hits: list[Hit], enabled: set[str]) -> list[Hit]:
    return [h for h in hits if h.detector_id.split(".", 1)[0] in enabled]


def _match_rule(
    rule_detector: str,
    rule_upstream: str | None,
    rule_tool: str | None,
    hit: Hit,
    upstream: str,
    tool: str | None,
) -> bool:
    from sluice.detectors.base import match_detector_pattern

    if not match_detector_pattern(rule_detector, hit.detector_id):
        return False
    if rule_upstream and not fnmatch.fnmatch(upstream, rule_upstream):
        return False
    if rule_tool and tool and not fnmatch.fnmatch(tool, rule_tool):
        return False
    return True


def resolve_action(
    hits: list[Hit],
    cfg: SluiceConfig,
    upstream: str,
    tool: str | None,
) -> ResolvedAction | None:
    if not hits:
        return None

    for rule in cfg.policy.rules:
        matching = [
            h
            for h in hits
            if _match_rule(rule.detector, rule.upstream, rule.tool, h, upstream, tool)
        ]
        if matching:
            return ResolvedAction(
                action=rule.action,
                rule_detector=rule.detector,
                preset_source=rule.preset_source,
                hits=matching,
            )

    return ResolvedAction(
        action=cfg.policy.default_action,
        rule_detector="default",
        preset_source=None,
        hits=hits,
    )


def evaluate(
    raw: str,
    context: ScanContext,
    cfg: SluiceConfig,
) -> tuple[str, PolicyViolation | None, list[Hit]]:
    enabled = _enabled_categories(cfg)
    hits = _filter_hits(scan_all(raw, context), enabled)
    if not hits:
        return raw, None, []

    resolved = resolve_action(hits, cfg, context.upstream, context.tool)
    if resolved is None:
        return raw, None, []

    if resolved.action == "block":
        primary = resolved.hits[0]
        log.warning(
            "policy_block",
            detector=primary.detector_id,
            upstream=context.upstream,
            tool=context.tool,
        )
        return raw, PolicyViolation(
            rule=primary.detector_id,
            detail=f"Refusing call: matched {primary.label} during {context.method or context.direction}.",
            action="block",
            detectors=[h.detector_id for h in resolved.hits],
            preset_source=resolved.preset_source,
        ), hits

    if resolved.action == "redact":
        body = raw
        secret_hits = [h for h in hits if h.detector_id.startswith("secrets.")]
        pii_hits = [h for h in hits if h.detector_id.startswith("pii.")]
        if secret_hits:
            body, _ = secrets_detector.redact(body, secret_hits)
        if pii_hits:
            body, _ = pii_detector.redact(body, pii_hits)
        log.info("policy_redact", detectors=[h.detector_id for h in hits], upstream=context.upstream)
        return body, PolicyViolation(
            rule="redacted",
            detail=f"Removed sensitive fragments before forwarding ({context.method or context.direction}).",
            action="redact",
            detectors=[h.detector_id for h in hits],
            preset_source=resolved.preset_source,
        ), hits

    if resolved.action == "flag":
        log.info("policy_flag", detectors=[h.detector_id for h in hits], upstream=context.upstream)
        return raw, PolicyViolation(
            rule=resolved.hits[0].detector_id,
            detail=f"Flagged '{resolved.hits[0].label}' in {context.method or context.direction}.",
            action="flag",
            detectors=[h.detector_id for h in hits],
            preset_source=resolved.preset_source,
        ), hits

    return raw, None, hits


def bootstrap_detectors() -> None:
    load_entry_point_detectors()
    _ = get_registry()
