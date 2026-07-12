from __future__ import annotations

import subprocess
import time
from pathlib import Path

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MOCK_SERVER = ROOT / "tests" / "integration" / "mock_mcp_server.py"


@pytest.fixture
def integration_config(tmp_path: Path) -> Path:
    cfg = {
        "version": 1,
        "proxy": {"host": "127.0.0.1", "port": 0},
        "upstreams": [
            {
                "name": "mock",
                "transport": "stdio",
                "command": "python3",
                "args": [str(MOCK_SERVER)],
            }
        ],
        "routing": {"default": "mock"},
        "policy": {
            "rules": [
                {"detector": "secrets.*", "action": "flag"},
                {"detector": "pii.*", "action": "redact"},
            ],
            "default_action": "pass",
        },
        "taint": {"enabled": True, "min_length": 12, "provenance": True},
        "dashboard": {"enabled": False},
        "audit": {
            "sink": "sqlite",
            "sqlite": {"path": str(tmp_path / "audit.db"), "retention_days": 1},
        },
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    return path


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.integration
def test_secret_blocked_on_request(integration_config: Path):
    port = _free_port()
    data = yaml.safe_load(integration_config.read_text())
    data["proxy"]["port"] = port
    data["policy"]["rules"][0]["action"] = "block"
    integration_config.write_text(yaml.safe_dump(data, sort_keys=False))

    proc = subprocess.Popen(
        ["python3", "-m", "sluice", "serve", "--config", str(integration_config)],
        cwd=ROOT,
    )
    try:
        for _ in range(40):
            try:
                httpx.get(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            pytest.fail("sluice did not start")

        resp = httpx.post(
            f"http://127.0.0.1:{port}/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "send_email",
                    "arguments": {"body": "AKIAIOSFODNN7EXAMPLE"},
                },
            },
            timeout=5,
        )
        body = resp.json()
        assert "error" in body
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.mark.integration
def test_taint_leak_blocked_after_response(integration_config: Path):
    port = _free_port()
    data = yaml.safe_load(integration_config.read_text())
    data["proxy"]["port"] = port
    integration_config.write_text(yaml.safe_dump(data, sort_keys=False))

    proc = subprocess.Popen(
        ["python3", "-m", "sluice", "serve", "--config", str(integration_config)],
        cwd=ROOT,
    )
    try:
        for _ in range(40):
            try:
                httpx.get(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            pytest.fail("sluice did not start")

        session = "test-session-123"
        headers = {"Mcp-Session-Id": session, "Content-Type": "application/json"}

        read_resp = httpx.post(
            f"http://127.0.0.1:{port}/",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
            },
            timeout=5,
        )
        assert "result" in read_resp.json()

        leak_resp = httpx.post(
            f"http://127.0.0.1:{port}/",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "send_email",
                    "arguments": {"body": "AKIAIOSFODNN7EXAMPLE"},
                },
            },
            timeout=5,
        )
        body = leak_resp.json()
        assert "error" in body
        assert "already appeared" in body["error"]["message"].lower()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
