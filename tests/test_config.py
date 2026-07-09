
import pytest
import yaml

from sluice.config.loader import load_config
from sluice.config.migrate import is_legacy_config, migrate_legacy_config


def test_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("SLUICE_TEST_TOKEN", "secret-value")
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "upstreams": [
                    {
                        "name": "api",
                        "transport": "http",
                        "url": "http://localhost:9",
                        "headers": {"Authorization": "${SLUICE_TEST_TOKEN}"},
                    }
                ],
            }
        )
    )
    cfg = load_config(cfg_path, write_migration=False)
    assert cfg.upstreams[0].headers["Authorization"] == "secret-value"


def test_legacy_migration_writes_upgraded_file(tmp_path):
    legacy = tmp_path / "config.yaml"
    legacy.write_text(
        yaml.safe_dump(
            {
                "transport": "http",
                "upstream": {"url": "http://localhost:3000"},
            }
        )
    )
    raw = yaml.safe_load(legacy.read_text())
    assert is_legacy_config(raw)
    migrated = migrate_legacy_config(raw)
    assert migrated["version"] == 1
    assert migrated["upstreams"][0]["name"] == "default"

    load_config(legacy, write_migration=True)
    upgraded = tmp_path / "config.yaml.upgraded"
    assert upgraded.exists()
    data = yaml.safe_load(upgraded.read_text())
    assert data["upstreams"][0]["name"] == "default"


def test_missing_env_raises(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "upstreams": [
                    {"name": "x", "transport": "http", "url": "${MISSING_VAR_XYZ}"}
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="environment variable not set"):
        load_config(cfg_path, write_migration=False)
