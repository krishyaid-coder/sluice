#!/usr/bin/env python3
"""Minimal stdio MCP server for Sluice integration tests."""
from __future__ import annotations

import json
import sys

SECRET = "AKIAIOSFODNN7EXAMPLE"


def respond(req: dict) -> dict:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp", "version": "0.0.1"},
            },
        }

    if method == "notifications/initialized":
        return {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file",
                        "inputSchema": {"type": "object"},
                    },
                    {
                        "name": "send_email",
                        "description": "Send email",
                        "inputSchema": {"type": "object"},
                    },
                ]
            },
        }

    if method == "tools/call":
        tool = req.get("params", {}).get("name")
        if tool == "read_file":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"file contains {SECRET}"}]
                },
            }
        if tool == "send_email":
            body = json.dumps(req.get("params", {}))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": f"sent {body}"}]},
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"unknown method {method}"},
    }


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if req.get("method") == "notifications/initialized":
            continue
        out = respond(req)
        if out:
            print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
