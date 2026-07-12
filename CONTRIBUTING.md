# Contributing to Sluice

## Development setup

```bash
git clone https://github.com/krishyaid-coder/sluice.git
cd sluice
pip install -e ".[dev]"
pytest tests/ -v -m "not integration"
pytest tests/integration -v -m integration
```

## Adding a detector

1. Copy an existing detector under `sluice/detectors/` (e.g. `prompt_injection.py`)
2. Implement `scan(text, context) -> list[Hit]` — pure function, no I/O
3. Register with `@register` for in-tree detectors, or via entry point for external packages
4. Add policy rules in `config.yaml.example`
5. Add tests under `tests/`
6. Update `docs/detectors.md`

### Entry point (external package)

```toml
[project.entry-points."sluice.detectors"]
my_org_secrets = "my_org_sluice_extras:MyOrgSecretsDetector"
```

### In-tree registration

Import your module from `sluice/policy/engine.py` so it loads at bootstrap:

```python
from sluice.detectors import my_detector  # noqa: F401
```

## Policy presets

Presets live in `sluice/policy/presets/*.yaml`. Each file contributes `policy.rules` and optional `detectors` toggles — never `upstreams`.

Add a preset:

1. Create `sluice/policy/presets/myserver.yaml`
2. Add `preset_source: myserver` on each rule
3. Add a test in `tests/test_v03_features.py` that `list_presets()` includes it

## Pull requests

Keep changes focused. Run before opening a PR:

```bash
ruff check sluice tests
pytest tests/ -v
```

## Security

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## User documentation

End-to-end setup and validation: [docs/guide.md](docs/guide.md)
