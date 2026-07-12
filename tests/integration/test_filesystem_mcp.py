from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _npx_available() -> bool:
    return shutil.which("npx") is not None


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def filesystem_config(tmp_path: Path) -> Path:
    cfg = {
        "version": 1,
        "proxy": {"host": "127.0.0.1", "port": 0},
        "upstreams": [
            {
                "name": "filesystem",
                "transport": "stdio",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)],
            }
        ],
        "routing": {"default": "filesystem"},
        "policy": {"rules": [], "default_action": "pass"},
        "taint": {"enabled": False},
        "dashboard": {"enabled": False},
        "audit": {"sink": "stdout"},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    return path


@pytest.mark.integration
@pytest.mark.skipif(not _npx_available(), reason="npx not installed")
def test_real_filesystem_mcp_tools_list(filesystem_config: Path, tmp_path: Path):
    port = _free_port()
    data = yaml.safe_load(filesystem_config.read_text())
    data["proxy"]["port"] = port
    filesystem_config.write_text(yaml.safe_dump(data, sort_keys=False))

    proc = subprocess.Popen(
        ["python3", "-m", "sluice", "serve", "--config", str(filesystem_config)],
        cwd=ROOT,
    )
    try:
        for _ in range(60):
            try:
                httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
                break
            except httpx.HTTPError:
                time.sleep(0.5)
        else:
            pytest.fail("sluice did not start in time (npx cold start may be slow)")

        resp = httpx.post(
            f"http://127.0.0.1:{port}/",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            timeout=30.0,
        )
        body = resp.json()
        assert "result" in body
        tools = body["result"].get("tools", [])
        assert any(t.get("name") == "read_file" for t in tools)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
