# Sluice Detector Catalogue

Built-in detectors and how to extend them.

## Built-in detectors

| Category | ID prefix | Scope | Default policy in `sluice init` |
|---|---|---|---|
| Secrets | `secrets.*` | Request + response | `block` |
| PII | `pii.*` | Request + response | `redact` |
| Tool poisoning | `tool_poisoning.*` | `tools/list` responses only | `flag` |
| Prompt injection | `prompt_injection.*` | Tool responses (`tools/call`, etc.) | `flag` |
| Taint leak | `taint_leak` | Outbound requests (internal) | always `block` |

### Secrets (`sluice/detectors/secrets.py`)

- AWS access key patterns
- High-entropy strings (configurable threshold)
- Common API key prefixes

### PII (`sluice/detectors/pii.py`)

- Email addresses
- Credit card numbers (Luhn-checked)
- Singapore NRIC / phone patterns (extensible)

### Tool poisoning (`sluice/detectors/tool_poisoning.py`)

Scans tool metadata on `tools/list` responses:

- "ignore previous instructions" phrases
- System-role override language
- Hidden HTML comments and zero-width characters
- Exfiltration wording in descriptions/schemas

### Prompt injection (`sluice/detectors/prompt_injection.py`)

Scans arbitrary tool **response** bodies for the same heuristic families plus jailbreak phrases (`DAN mode`, `disable guardrails`, etc.).

## Policy matching

Rules are evaluated **top to bottom**. First match wins.

```yaml
policy:
  rules:
    - detector: secrets.*
      action: block
      upstream: github
      tool: "create_*"
```

- `detector` — glob on detector id (`secrets.*`, `pii.email`, `*`)
- `upstream` — optional glob on upstream name
- `tool` — optional glob on tool name from `tools/call`

## Custom detectors

### In-tree

1. Create `sluice/detectors/my_detector.py`
2. Implement a class with `id`, `category`, `severity`, and `scan(text, context) -> list[Hit]`
3. Call `register(MyDetector())` at module bottom
4. Import the module from `sluice/policy/engine.py` bootstrap
5. Add tests in `tests/`

### External package (entry point)

```toml
[project.entry-points."sluice.detectors"]
acme_secrets = "acme_sluice_extras:AcmeSecretsDetector"
```

```python
from sluice.detectors.base import Hit, ScanContext, register

class AcmeSecretsDetector:
    id = "acme.secrets"
    category = "secrets"
    severity = "high"

    def scan(self, text: str, context: ScanContext) -> list[Hit]:
        ...
```

Add a policy rule:

```yaml
policy:
  rules:
    - detector: acme.secrets
      action: block
```

## Hit structure

```python
Hit(
    detector_id="secrets.aws_key",
    start=10,
    end=30,
    matched="AKIA...",
    label="AWS access key",
    severity="critical",
)
```

Detectors must be pure: no I/O, no global mutation.

## Session taint interaction

When a response hit is `flag` or `redact`, the matched substring is stored per session. v0.3 also records JSON paths when `taint.provenance: true`.

The next outbound request containing that substring is blocked with `taint_leak` before detectors run.
