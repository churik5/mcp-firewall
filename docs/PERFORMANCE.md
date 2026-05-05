# Performance

Three numbers matter for `bulwark-mcp`:

1. The rules detector latency. It runs on every frame.
2. The inspector cache-hit path. It's the fast path once Ollama has classified a piece of text once.
3. The end-to-end proxy round-trip with `cat` as the upstream server. This is the closest thing to "what your real MCP server will feel like" without picking one specific server.

All three are bounded budgets, asserted in CI by `tests/test_perf.py`. The numbers below are what we measured on the maintainer's machine; yours will differ. Run `bulwark benchmark` and send a row to the table at the bottom of this doc — that's how we'll find regressions on the long tail of consumer hardware before our users do.

## Budgets (ADR-0004 §7)

| Path                                     | p95 budget |
|------------------------------------------|-----------:|
| Rules detector                           | ≤ 5 ms     |
| Inspector with rules short-circuit       | ≤ 10 ms    |
| Inspector with classifier cache hit      | ≤ 10 ms    |
| Inspector with LLM (cache miss)          | ≤ 200 ms   |
| Hard inspector abort threshold           | 250 ms     |

Anything beyond the abort threshold falls back to `verdict=WARN, note=inspection_timeout` and forwards the original frame. The pump is never stalled past 250 ms by the detector itself, even if Ollama is having a bad day.

## Measured on a 2024 MacBook Pro (M-series, 16 GB)

`pytest tests/test_perf.py -s` produces:

```
[bench] rules s2c (clean text):    p50=0.04 ms  p95=0.04 ms
[bench] rules s2c (attack):        p50=0.02 ms  p95=0.02 ms
[bench] inspector short-circuit:   p50=0.03 ms  p95=0.03 ms
[bench] inspector cache-hit:       p50=0.12 ms  p95=0.13 ms
```

`bulwark benchmark` adds the end-to-end number:

```
workload                            iters    p50    p95    p99
rules detector (benign s2c)         200     0.04   0.04   0.05
inspector cache-hit                 200     0.13   0.16   0.19
end-to-end (cat server)             50      8.10   12.40  18.20
```

The end-to-end number includes one process-spawn, two pump tasks, the audit-log queue write, and the round-trip back. ~8 ms p50 is mostly pipe buffering — the inspector itself is sub-millisecond on cache-hit content.

## Live Ollama (qwen2.5:3b, Q4_K_M, Apple Silicon)

Cold call (first run after server start): ~1.8 s. The model loads, the tokenizer warms, then steady state.

Warm calls: 140–180 ms p50, 163 ms max in a 5-call sample. That's well inside the 200 ms budget.

To pre-warm the model so your first inspected frame doesn't trip the inspector's hard abort:

```bash
curl -s http://localhost:11434/api/generate \
    -d '{"model":"qwen2.5:3b","prompt":"warmup","stream":false}' >/dev/null
bulwark run --server "..." --detector
```

## Community data (filled in by users)

Run `bulwark benchmark` on your own hardware and open a PR adding a row. Format below:

| Hardware                              | OS         | Python | rules p95 | cache-hit p95 | E2E p95 | Notes |
|---------------------------------------|------------|--------|----------:|--------------:|--------:|-------|
| MacBook Pro M2, 16 GB                 | macOS 14.5 | 3.12   | 0.04 ms   | 0.13 ms       | 12.4 ms | reference numbers, maintainer's machine |
| _your row here_                       |            |        |           |               |         |       |

If your numbers are wildly different from the reference (say, p95 over 1 ms on rules), that's worth an issue. Either the regex pack hit a degenerate case on your traffic shape, or something else on the box is contending for CPU.

## Where to look when things drift

- **`det_latency_ms` column in the audit log.** Per-frame inspector latency. `bulwark logs --tail 200` makes it easy to scan.
- **Classifier cache.** `sqlite3 data/log.db 'SELECT COUNT(*) FROM classifier_cache;'` — if this number isn't growing during a session, the cache isn't being hit, which usually means content is varied enough that 24 h TTL doesn't help. Raise `cache_ttl_s` if your workload is repetitive.
- **Circuit breaker state.** Stderr logs `ollama: call failed (N/3)` when the breaker is approaching open. Three failures and you're in rules-only for a minute. Look at the Ollama process; that's where the problem is.

## What we're NOT measuring (yet)

- Memory footprint over time. `bulwark-mcp` keeps the audit-log queue at most 10 000 events deep by default; in steady state the resident set is dominated by Python + the sqlite + httpx pages. v0.5 will add a `bulwark stats --memory` view if there's demand.
- Throughput beyond ~1 000 events / second. Above that, the audit-log queue becomes the bottleneck, not the detector. Most realistic MCP traffic is in the 1–10 events/second range.
- Cross-platform numbers. We have CI on Ubuntu and dev on macOS. Windows isn't tested — patches welcome.
