"""Latency benchmarks for the inspection pipeline."""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time

from sluice.config.schema import PolicyConfig, PolicyRule, SluiceConfig
from sluice.proxy.pipeline import Pipeline

CLEAN_MSG = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
SECRET_MSG = (
    '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
    '"params":{"name":"write","arguments":{"x":"AKIAIOSFODNN7EXAMPLE"}}}'
)

BUDGET_MS = {
    "clean_p95": 5.0,
    "secret_p95": 20.0,
}


def _cfg() -> SluiceConfig:
    return SluiceConfig(
        upstreams=[{"name": "bench", "transport": "http", "url": "http://127.0.0.1:9"}],
        policy=PolicyConfig(rules=[PolicyRule(detector="secrets.*", action="block")]),
        audit={"sink": "stdout"},
    )


async def _run_case(pipeline: Pipeline, raw: str, iterations: int = 500) -> list[float]:
    latencies: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        await pipeline.inspect_request(raw, session_id="bench", upstream="bench")
        latencies.append((time.perf_counter_ns() - start) / 1_000_000)
    return latencies


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(len(ordered) * 0.95) - 1
    return ordered[max(0, idx)]


async def run_benchmark(*, quiet: bool = False) -> dict[str, float]:
    import logging

    if quiet:
        logging.disable(logging.CRITICAL)
    pipeline = Pipeline(_cfg(), audit=None)
    clean = await _run_case(pipeline, CLEAN_MSG)
    secret = await _run_case(pipeline, SECRET_MSG, iterations=200)
    return {
        "clean_p50": statistics.median(clean),
        "clean_p95": _p95(clean),
        "secret_p50": statistics.median(secret),
        "secret_p95": _p95(secret),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Sluice pipeline latency benchmark")
    parser.add_argument("--budget", action="store_true", help="Exit non-zero if over budget")
    args = parser.parse_args()

    results = asyncio.run(run_benchmark(quiet=args.budget))
    print("Sluice pipeline latency (ms)")
    print(f"  clean  p50={results['clean_p50']:.2f}  p95={results['clean_p95']:.2f}")
    print(f"  secret p50={results['secret_p50']:.2f}  p95={results['secret_p95']:.2f}")

    if args.budget:
        failed = []
        if results["clean_p95"] > BUDGET_MS["clean_p95"]:
            failed.append(f"clean p95 {results['clean_p95']:.2f}ms > {BUDGET_MS['clean_p95']}ms")
        if results["secret_p95"] > BUDGET_MS["secret_p95"]:
            failed.append(f"secret p95 {results['secret_p95']:.2f}ms > {BUDGET_MS['secret_p95']}ms")
        if failed:
            raise SystemExit("budget exceeded: " + "; ".join(failed))


if __name__ == "__main__":
    main()
