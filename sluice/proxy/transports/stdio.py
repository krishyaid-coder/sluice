from __future__ import annotations

import json
import sys

import structlog

from sluice.proxy.pipeline import Pipeline
from sluice.proxy.router import Router, new_session_id

log = structlog.get_logger()


class StdioTransport:
    def __init__(self, upstream_name: str):
        self._upstream_name = upstream_name
        self._session_id = new_session_id()

    async def run(self, pipeline: Pipeline, router: Router) -> None:
        upstream = router.resolve_upstream(self._upstream_name)
        log.info("stdio_transport_starting", upstream=upstream, session_id=self._session_id)

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            req_id = pipeline.request_id_from_raw(line)
            clean, violation = await pipeline.inspect_request(
                line, session_id=self._session_id, upstream=upstream
            )

            if violation and violation.action == "block":
                print(pipeline.block_response(req_id, violation.detail), flush=True)
                continue

            try:
                rpc = json.loads(clean)
                request = __import__(
                    "sluice.proxy.models", fromlist=["JSONRPCRequest"]
                ).JSONRPCRequest.model_validate(rpc)
                response = await router.dispatch(upstream, request, self._session_id)
            except Exception as e:
                log.error("stdio_forward_failed", error=str(e))
                print(
                    pipeline.block_response(req_id, f"Upstream error: {e}"),
                    flush=True,
                )
                continue

            resp_raw = json.dumps(response.model_dump(exclude_none=True))
            method = request.method
            clean_resp, resp_violation = await pipeline.inspect_response(
                resp_raw,
                session_id=self._session_id,
                upstream=upstream,
                method=method,
            )

            if resp_violation and resp_violation.action == "block":
                print(
                    pipeline.block_response(req_id, "Upstream response failed policy."),
                    flush=True,
                )
                continue

            print(clean_resp, flush=True)

    async def shutdown(self) -> None:
        return None
