from __future__ import annotations

from typing import Protocol

from sluice.proxy.pipeline import Pipeline
from sluice.proxy.router import Router


class Transport(Protocol):
    async def run(self, pipeline: Pipeline, router: Router) -> None: ...
    async def shutdown(self) -> None: ...
