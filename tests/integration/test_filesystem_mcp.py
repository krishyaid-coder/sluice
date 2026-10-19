from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]

# Official filesystem MCP renamed read_file → read_text_file; accept both.
_FILE_TOOLS = {"read_file", "read_text_file"}


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


def _wait_health(port: int) -> None:
    for _ in range(60):
        try:
            resp = httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
            if resp.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.5)
    pytest.fail("sluice did not start in time (npx cold start may be slow)")


def _rpc(
    port: int,
    payload: dict,
    *,
    session: dict[str, str],
    timeout: float = 30.0,
    retries: int = 1,
) -> dict:
    last: dict | str | None = None
    for attempt in range(retries):
        try:
            resp = httpx.post(
                f"http://127.0.0.1:{port}/",
                json=payload,
                headers=session,
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            last = str(exc)
            time.sleep(1.0)
            continue
        sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        if sid:
            session["Mcp-Session-Id"] = sid
        body = resp.json()
        if resp.status_code == 200 and (
            payload.get("id") is None or "result" in body or "error" in body
        ):
            return body
        last = body
        if resp.status_code == 502 and attempt + 1 < retries:
            time.sleep(1.0)
            continue
        break
    pytest.fail(f"upstream RPC failed: {last!r}")


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
        _wait_health(port)
        session: dict[str, str] = {}

        # Real MCP servers do not answer tools/list until the handshake completes.
        # First RPC also spawns `npx -y`, so retry while the package boots.
        init = _rpc(
            port,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "sluice-integration", "version": "0"},
                },
            },
            session=session,
            timeout=60.0,
            retries=45,
        )
        assert "result" in init, init

        _rpc(
            port,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session=session,
            retries=3,
        )

        body = _rpc(
            port,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            session=session,
        )
        assert "result" in body, body
        tools = body["result"].get("tools", [])
        names = {t.get("name") for t in tools}
        assert names & _FILE_TOOLS, names
    finally:
        proc.terminate()
        proc.wait(timeout=10)
