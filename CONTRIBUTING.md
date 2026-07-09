# Contributing to Sluice

## Development setup

```bash
git clone https://github.com/krishyaid-coder/sluice.git
cd sluice
pip install -e ".[dev]"
pytest tests/ -v
```

## Adding a detector

1. Create a class in `sluice/detectors/` implementing `scan(text, context) -> list[Hit]`
2. Register it in `sluice/detectors/base.py` or via the `sluice.detectors` entry point group
3. Add policy rules in `config.yaml.example`
4. Add tests under `tests/`

## Pull requests

Keep changes focused. Run `ruff check sluice tests` and `pytest` before opening a PR.

## Security

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.
