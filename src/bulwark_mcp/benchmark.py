"""bulwark benchmark — measure local detection latency.

Runs three workloads on the user's machine and prints p50 / p95 / p99
plus a one-line tip per outlier:

1. Rules detector on a benign s2c text (~200 chars).
2. Inspector cache-hit path (rules short-circuit, classifier cache
   pre-warmed).
3. End-to-end `python -m bulwark_mcp run --server cat` round-trip
   for a single tool result frame, including audit-log write.

The point isn't to be a synthetic benchmark — it's to give the user a
believable number on their hardware before they decide to deploy us
in front of a noisy MCP server. Report numbers in `docs/PERFORMANCE.md`
when filing a bug; the table there is community-collected.

Cost: ~3-5 s wall-clock total. Safe to run any time.
"""

from __future__ import annotations

import asyncio
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import Settings
from .detectors.llm import OllamaClassifier
from .detectors.rules import RulesEngine
from .inspector import Inspector
from .models import parse_frame
from .policy import default_policy
from .storage import Storage


@dataclass(frozen=True)
class BenchResult:
    name: str
    iterations: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    note: str | None = None


# ---------------------------------------------------------------------
# The three workloads
# ---------------------------------------------------------------------


_BENIGN_TEXT = (
    "The function returns the user's profile as a JSON object. "
    "Available fields are 'name', 'email', 'created_at', and 'plan'."
)


def _bench_rules(rules: RulesEngine, *, iters: int) -> BenchResult:
    samples: list[float] = []
    for _ in range(20):  # warm-up
        rules.detect(_BENIGN_TEXT, direction="server_to_client")
    for _ in range(iters):
        t0 = time.perf_counter()
        rules.detect(_BENIGN_TEXT, direction="server_to_client")
        samples.append((time.perf_counter() - t0) * 1000.0)
    return BenchResult(
        name="rules detector (benign s2c)",
        iterations=iters,
        p50_ms=_pct(samples, 0.50),
        p95_ms=_pct(samples, 0.95),
        p99_ms=_pct(samples, 0.99),
    )


async def _bench_inspector_cache_hit(
    rules: RulesEngine, storage: Storage, *, iters: int
) -> BenchResult:
    """Cache-hit path: pre-seed the classifier cache, then time how
    fast the inspector returns when every Ollama call is short-circuited."""
    raw = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": _BENIGN_TEXT}]},
        },
        separators=(",", ":"),
    )
    parsed, _ = parse_frame(raw)

    classifier = OllamaClassifier(
        storage=storage,
        transport=httpx.MockTransport(
            lambda _r: httpx.Response(
                200,
                json={"response": "DATA"},
                request=httpx.Request("POST", "http://localhost:11434/api/generate"),
            )
        ),
    )
    try:
        insp = Inspector(rules=rules, classifier=classifier, policy=default_policy())
        # First call seeds the cache.
        await insp.inspect(raw=raw, parsed=parsed, direction="server_to_client")
        for _ in range(20):
            await insp.inspect(raw=raw, parsed=parsed, direction="server_to_client")
        samples: list[float] = []
        for _ in range(iters):
            t0 = time.perf_counter()
            await insp.inspect(raw=raw, parsed=parsed, direction="server_to_client")
            samples.append((time.perf_counter() - t0) * 1000.0)
    finally:
        await classifier.aclose()

    return BenchResult(
        name="inspector cache-hit",
        iterations=iters,
        p50_ms=_pct(samples, 0.50),
        p95_ms=_pct(samples, 0.95),
        p99_ms=_pct(samples, 0.99),
    )


async def _bench_end_to_end(*, iters: int) -> BenchResult:
    """Spawn `python -m bulwark_mcp run --server cat`, send N benign
    frames on stdin, read N echoes from stdout, time each round-trip."""
    bench_db = Path(tempfile.gettempdir()) / "bulwark-mcp-bench.db"
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "bulwark_mcp",
        "run",
        "--server",
        "cat",
        "--db-path",
        str(bench_db),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    frame = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": _BENIGN_TEXT}]},
            },
            separators=(",", ":"),
        )
        + "\n"
    ).encode()

    samples: list[float] = []
    try:
        # Warm-up
        for _ in range(5):
            proc.stdin.write(frame)
            await proc.stdin.drain()
            await proc.stdout.readline()
        for _ in range(iters):
            t0 = time.perf_counter()
            proc.stdin.write(frame)
            await proc.stdin.drain()
            line = await proc.stdout.readline()
            samples.append((time.perf_counter() - t0) * 1000.0)
            if not line:
                break
    finally:
        proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except TimeoutError:
            proc.kill()
            await proc.wait()

    if not samples:
        return BenchResult(
            name="end-to-end (cat server)",
            iterations=0,
            p50_ms=0.0,
            p95_ms=0.0,
            p99_ms=0.0,
            note="proxy did not echo any frames — see stderr",
        )

    return BenchResult(
        name="end-to-end (cat server)",
        iterations=len(samples),
        p50_ms=_pct(samples, 0.50),
        p95_ms=_pct(samples, 0.95),
        p99_ms=_pct(samples, 0.99),
    )


# ---------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------


async def run_benchmarks(settings: Settings, *, iters: int = 200) -> list[BenchResult]:
    rules = RulesEngine.from_directory(settings.detector.rules_dir)
    results: list[BenchResult] = [_bench_rules(rules, iters=iters)]

    storage = Storage(settings.db_path)
    await storage.open()
    try:
        results.append(await _bench_inspector_cache_hit(rules, storage, iters=iters))
    finally:
        await storage.close()

    results.append(await _bench_end_to_end(iters=min(iters, 50)))
    return results


def run_benchmarks_sync(settings: Settings, *, iters: int = 200) -> list[BenchResult]:
    return asyncio.run(run_benchmarks(settings, iters=iters))


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _pct(samples: list[float], p: float) -> float:
    if not samples:
        return 0.0
    s = sorted(samples)
    if len(s) == 1:
        return s[0]
    rank = (len(s) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(s) - 1)
    frac = rank - lo
    return s[lo] + (s[hi] - s[lo]) * frac


# Kept for type-checker / future use; not called yet.
_BenchFn = Callable[[], Awaitable[BenchResult]]
_ = statistics  # imported for percentile-style helpers in v0.5
