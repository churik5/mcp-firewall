# Detection layer performance

ADR-0004 §7 sets these latency budgets for the inspector path:

| Path                                | Budget       |
|-------------------------------------|--------------|
| Rules detector                      | ≤5 ms p95    |
| Rules short-circuit (LLM skipped)   | ≤10 ms p95   |
| Inspector with classifier cache hit | ≤10 ms p95   |
| Inspector with LLM (cache miss)     | ≤200 ms p95  |
| Hard inspector abort threshold      | 250 ms       |

## Synthetic benchmark (M-series Mac, Python 3.12, no I/O contention)

Measured by `tests/test_perf.py` over 200 iterations after a 20-iter
warm-up. Numbers below are typical — your CI host may be slower.

| Path                                | p50    | p95    | budget |
|-------------------------------------|--------|--------|--------|
| Rules s2c (clean text)              | 0.04   | 0.04   | 5      |
| Rules s2c (attack payload)          | 0.02   | 0.02   | 5      |
| Inspector short-circuit (rules ≥0.9)| 0.03   | 0.03   | 10     |
| Inspector cache hit                 | 0.12   | 0.13   | 10     |

All synthetic paths beat their budgets by **≥75×**. The mock-transport
classifier overhead is what shows up in the cache-hit path (network
serialisation cost is zero, but we still hit SQLite for the lookup).

## Real Ollama benchmark (`qwen2.5:3b` Q4_K_M, Apple Silicon)

```
cold     1817 ms   (first call ever — model load + tokenizer warmup)
warm 1   183 ms    (model resident, fresh content)
cache    0 ms      (sqlite lookup short-circuit)
fresh×5  140 ± 12 ms p50, 163 ms max
```

Cold call busts the 200 ms p95 budget — that is **expected** and
covered by ADR-0004 §7's hard-abort path: the inspector wraps the call
in `asyncio.wait_for(timeout=200ms)`, the cold call times out, and the
first inspected frame returns `verdict=WARN, note=inspection_timeout`
instead of stalling the pump. Subsequent frames stay under budget.

If you need predictable latency on first frame, run Ollama in advance
and warm the model with a single prompt before launching the proxy:

```bash
curl -s http://localhost:11434/api/generate \
    -d '{"model":"qwen2.5:3b","prompt":"warmup","stream":false}' >/dev/null
bulwark run --server "..." --detector
```

## Where to look if latency drifts

- `det_latency_ms` column in the audit log is per-frame inspector latency.
  `bulwark logs --tail 200` makes it easy to scan.
- The classifier cache lives in `classifier_cache` (sha256-keyed); a
  noisy hash distribution there means content is varied enough that
  the cache rarely hits — consider raising `cache_ttl_s` if the
  workload is repetitive.
- The circuit breaker opens after 3 consecutive Ollama failures and
  stays open 60 s. While open, every frame skips the LLM and spends
  ~5 ms in the rules path. `det_classifier=NULL` with
  `note='circuit_open'` is the fingerprint.
