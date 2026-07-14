"""Regression tests for StdioUpstream JSON-RPC id correlation.

Prior implementation did one readline() per request under a lock and assumed
that line was the response. Any stray stdout, notification, or out-of-order
response would silently desync request/response pairing — a wrong response
could get returned to the agent without being scanned against the correct
request's context.

These tests spawn small Python scripts as stdio "servers" that emit exactly
the misbehaviors that trip the old code.
"""

from __future__ import annotations

import sys

import pytest

from sluice.config.schema import UpstreamConfig
from sluice.proxy.models import JSONRPCRequest
from sluice.proxy.router import StdioUpstream


def _upstream(script: str) -> StdioUpstream:
    """Spawn a StdioUpstream backed by an inline Python script."""
    cfg = UpstreamConfig(
        name="mock",
        transport="stdio",
        command=sys.executable,
        args=["-u", "-c", script],
    )
    return StdioUpstream(cfg)


# ---------------------------------------------------------------------------
# Happy path — sanity check that the refactor didn't break basic operation.
# ---------------------------------------------------------------------------

WELL_BEHAVED = r"""
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"ok": True, "echo_method": req.get("method")}}
    print(json.dumps(resp), flush=True)
"""


@pytest.mark.asyncio
async def test_happy_path_single_request():
    """One request, one response — the baseline."""
    up = _upstream(WELL_BEHAVED)
    try:
        req = JSONRPCRequest(id=1, method="ping")
        resp = await up.forward(req)
        assert resp.id == 1
        assert resp.result == {"ok": True, "echo_method": "ping"}
    finally:
        await up.aclose()


@pytest.mark.asyncio
async def test_happy_path_many_sequential_requests():
    """Sequential requests each get their own correct response."""
    up = _upstream(WELL_BEHAVED)
    try:
        for i in range(1, 11):
            resp = await up.forward(JSONRPCRequest(id=i, method=f"m{i}"))
            assert resp.id == i
            assert resp.result["echo_method"] == f"m{i}"
    finally:
        await up.aclose()


# ---------------------------------------------------------------------------
# The bug scenarios — these fail on the old (single-readline) implementation.
# ---------------------------------------------------------------------------

LOGS_TO_STDOUT_BEFORE_RESPONDING = r"""
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    # Simulate a Node MCP server doing console.log() to stdout before the response.
    print("2026-07-14 log: handling request", flush=True)
    print("[DEBUG] some diagnostic", flush=True)
    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"handled": True}}
    print(json.dumps(resp), flush=True)
"""


@pytest.mark.asyncio
async def test_stray_log_lines_do_not_break_correlation():
    """Server prints non-JSON log lines before each response.

    Old code: readline() returns the first log line, json.loads fails or
    returns garbage as the response, request breaks.
    New code: log lines are recognized as non-JSON, dropped, the actual
    response is matched by id.
    """
    up = _upstream(LOGS_TO_STDOUT_BEFORE_RESPONDING)
    try:
        resp = await up.forward(JSONRPCRequest(id=42, method="test"))
        assert resp.id == 42
        assert resp.result == {"handled": True}
    finally:
        await up.aclose()


EMITS_NOTIFICATION_BETWEEN_RESPONSES = r"""
import json, sys
# Emit an unsolicited notification before the first request even arrives.
print(json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}), flush=True)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"n": req["id"]}}
    print(json.dumps(resp), flush=True)
    # Emit a progress-style notification after each response.
    print(json.dumps({"jsonrpc": "2.0", "method": "notifications/progress",
                       "params": {"progress": 100}}), flush=True)
"""


@pytest.mark.asyncio
async def test_notifications_do_not_get_returned_as_responses():
    """Server intersperses id-less notifications with real responses.

    Old code: readline() might grab a notification (no id), pydantic
    validates it as a JSONRPCResponse with id=None, returns garbage.
    New code: no-id payloads are recognized as notifications and dropped;
    the real response is matched by id.
    """
    up = _upstream(EMITS_NOTIFICATION_BETWEEN_RESPONSES)
    try:
        r1 = await up.forward(JSONRPCRequest(id=1, method="a"))
        assert r1.id == 1
        assert r1.result == {"n": 1}
        r2 = await up.forward(JSONRPCRequest(id=2, method="b"))
        assert r2.id == 2
        assert r2.result == {"n": 2}
    finally:
        await up.aclose()


OUT_OF_ORDER_RESPONDER = r"""
import json, sys, time
# Buffer two requests, respond in reverse order.
buffered = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    buffered.append(req)
    if len(buffered) == 2:
        # Respond to the second request first.
        for req in reversed(buffered):
            resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"got": req["id"]}}
            print(json.dumps(resp), flush=True)
        buffered.clear()
"""


@pytest.mark.asyncio
async def test_out_of_order_responses_still_correlate():
    """Server sends response B before response A.

    Old code: A's caller reads the first line (which is B's response),
    thinks it's A's answer, returns wrong data. B's caller then reads A's
    response, same problem.
    New code: each response goes to its own id-keyed future.
    """
    import asyncio

    up = _upstream(OUT_OF_ORDER_RESPONDER)
    try:
        # Send both concurrently so the server can buffer both before responding.
        task_a = asyncio.create_task(up.forward(JSONRPCRequest(id="req-a", method="a")))
        task_b = asyncio.create_task(up.forward(JSONRPCRequest(id="req-b", method="b")))
        resp_a, resp_b = await asyncio.gather(task_a, task_b)
        assert resp_a.id == "req-a"
        assert resp_a.result == {"got": "req-a"}
        assert resp_b.id == "req-b"
        assert resp_b.result == {"got": "req-b"}
    finally:
        await up.aclose()


# ---------------------------------------------------------------------------
# Failure-mode tests — the fixes should surface errors clearly, not hang.
# ---------------------------------------------------------------------------

NEVER_RESPONDS = r"""
import sys, time
# Read requests but never respond. Time out cleanly rather than hanging forever.
for line in sys.stdin:
    time.sleep(60)
"""


@pytest.mark.asyncio
async def test_hanging_server_times_out_cleanly(monkeypatch):
    """No response ever comes back. forward() should raise, not hang."""
    from sluice.proxy import router

    # Shrink the timeout for the test so we don't wait 30s.
    monkeypatch.setattr(router, "STDIO_FORWARD_TIMEOUT_SECONDS", 0.5)

    up = _upstream(NEVER_RESPONDS)
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            await up.forward(JSONRPCRequest(id=1, method="test"))
    finally:
        await up.aclose()


@pytest.mark.asyncio
async def test_forward_rejects_notification_request():
    """A request with id=None is a notification, not a request. forward() should
    refuse it rather than get stuck waiting for a response that never comes."""
    up = _upstream(WELL_BEHAVED)
    try:
        with pytest.raises(ValueError, match="cannot forward a notification"):
            await up.forward(JSONRPCRequest(method="notifications/initialized"))
    finally:
        await up.aclose()


@pytest.mark.asyncio
async def test_duplicate_id_in_flight_raises():
    """Same id used twice while first is in flight should surface loudly."""
    import asyncio

    up = _upstream(NEVER_RESPONDS)
    try:
        first = asyncio.create_task(up.forward(JSONRPCRequest(id=1, method="a")))
        # Give the first request time to register itself.
        await asyncio.sleep(0.05)
        with pytest.raises(RuntimeError, match="already in flight"):
            await up.forward(JSONRPCRequest(id=1, method="b"))
        # Clean up the first task.
        first.cancel()
        try:
            await first
        except (asyncio.CancelledError, RuntimeError):
            pass
    finally:
        await up.aclose()
