from __future__ import annotations

import fnmatch
from dataclasses import dataclass

import structlog

from sluice.config.schema import SluiceConfig
from sluice.detectors import (
    pii,  # noqa: F401 — register detector
    prompt_injection,  # noqa: F401 — register detector
    secrets,  # noqa: F401 — register detector
    tool_poisoning,  # noqa: F401 — register detector
)
from sluice.detectors.base import (
    Hit,
    ScanContext,
    get_registry,
    load_entry_point_detectors,
    scan_all,
)
from sluice.proxy.models import PolicyViolation
from sluice.session import pseudonym as pseudonym_session

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
        # Single unified pass, sorted by start descending, so each replacement
        # only shifts bytes we've already processed. Prior two-pass (secrets
        # then pii) corrupted output when a secret preceded a pii match in the
        # same message — the pii offsets were stale against the mutated body.
        redactable = [
            h for h in hits if h.detector_id.split(".", 1)[0] in ("secrets", "pii")
        ]
        body = raw
        for h in sorted(redactable, key=lambda x: (x.start, -x.end), reverse=True):
            tag = h.detector_id.split(".")[-1].upper()
            body = body[: h.start] + f"[REDACTED-{tag}]" + body[h.end :]
        log.info("policy_redact", detectors=[h.detector_id for h in hits], upstream=context.upstream)
        return body, PolicyViolation(
            rule="redacted",
            detail=f"Removed sensitive fragments before forwarding ({context.method or context.direction}).",
            action="redact",
            detectors=[h.detector_id for h in hits],
            preset_source=resolved.preset_source,
        ), hits

    if resolved.action == "pseudonymize":
        # Pseudonymize is a response-direction action. On requests, the reverse
        # pass in the pipeline has already substituted any pseudonyms back to
        # real values that the tool needs. Any PII hit that remains in an
        # outbound request is AI-authored — coerce to flag so it's audited but
        # not re-pseudonymized (which would either loop or break the tool call).
        if context.direction == "request":
            log.warning(
                "pseudonymize_on_request_coerced_to_flag",
                detectors=[h.detector_id for h in hits],
                upstream=context.upstream,
            )
            return raw, PolicyViolation(
                rule=resolved.hits[0].detector_id,
                detail=(
                    f"PII observed in outbound request "
                    f"({context.method or context.direction}); "
                    f"pseudonymize is response-direction only, flagged."
                ),
                action="flag",
                detectors=[h.detector_id for h in hits],
                preset_source=resolved.preset_source,
            ), hits

        # Response direction: PII hits get a stable per-session pseudonym;
        # anything else that's sensitive (secrets) still goes through redact
        # in the same pass so a mixed message doesn't quietly leak a secret.
        # Uses the same sort-by-start-descending pattern as the redact path.
        body = raw
        substitutable = [
            h for h in hits if h.detector_id.split(".", 1)[0] in ("secrets", "pii")
        ]
        replaced_pii = 0
        for h in sorted(substitutable, key=lambda x: (x.start, -x.end), reverse=True):
            category = h.detector_id.split(".", 1)[0]
            if category == "pii":
                replacement = pseudonym_session.assign(
                    context.session_id, h.matched, h.detector_id
                )
                if replacement is None:
                    # Pseudonymization is disabled but the rule still fired.
                    # Fall back to redaction so the value never leaves in the clear.
                    tag = h.detector_id.split(".")[-1].upper()
                    replacement = f"[REDACTED-{tag}]"
                else:
                    replaced_pii += 1
            else:
                tag = h.detector_id.split(".")[-1].upper()
                replacement = f"[REDACTED-{tag}]"
            body = body[: h.start] + replacement + body[h.end :]
        log.info(
            "policy_pseudonymize",
            detectors=[h.detector_id for h in hits],
            upstream=context.upstream,
            replaced_pii=replaced_pii,
        )
        return body, PolicyViolation(
            rule="pseudonymized",
            detail=f"Replaced PII with pseudonyms before forwarding ({context.method or context.direction}).",
            action="pseudonymize",
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
