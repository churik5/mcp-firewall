# ADR-0004: Detection layer architecture

- **Status:** proposed
- **Date:** 2026-05-04
- **Deciders:** @churik
- **Supersedes performance claim:** ADR-0001 §Negative ("not acceptable for a real-time enforcement gate")
- **Extends schema:** ADR-0003 (`events` table, `note` column reservation)

## Context

Week 1 (ADR-0001 to ADR-0003) shipped a passive proxy: every JSON-RPC frame is forwarded with sub-50 ms overhead and asynchronously logged. ADR-0001 explicitly deferred real-time enforcement to this ADR; ADR-0003 reserved a `note` column for a future detector verdict.

Week 2 introduces a detection layer that:

- inspects MCP frames for prompt-injection markers using both deterministic rules and a small local LLM classifier;
- can REPLACE outbound tool-call results (server→client) when high-confidence threats are detected;
- is **off by default** — existing Week 1 users keep their latency profile until they opt in via `detector.enabled: true`;
- never breaks the proxy if the LLM backend (Ollama) is unavailable.

Four interactive forks were settled with the user before this ADR was written; they are listed in §10 below.

## Decision

### 1. Pipeline shape

```
        ┌──────────────┐                          ┌──────────────┐
client →│              │ ───── line ─────────────►│              │
        │   _pump      │                          │  MCP server  │
        │  (s2c side   │                          │  (subproc)   │
        │   shown)     │                          │              │
        │              │ ◄──── line ──────────────│              │
        └──────┬───────┘                          └──────────────┘
               │  raw + parsed frame
               ▼
        ┌──────────────┐                          ┌──────────────┐
        │  Inspector   │  Verdict ───────────────►│ EventBuffer  │ async
        │ (rules + LLM)│                          │  (Week 1)    │ batched
        └──────┬───────┘                          └──────────────┘
               │  action ∈ {allow, warn, block}
               ▼
        ┌──────────────┐
        │  Replacement │  ← only when action == block
        │  composer    │
        └──────────────┘
```

When `detector.enabled=false` the pump keeps its Week 1 read → write → log order — no inspector calls, no extra latency, byte-for-byte forwarding. When enabled, the order becomes **read → inspect → (write original or replacement) → log with verdict**. The change is local to `_pump`; storage and CLI gain new columns/commands but their existing surface is unchanged.

### 2. Detector cascade

Only **server→client** (s2c) frames invoke the LLM detector. **client→server** (c2s) frames go through rules only — short tool-call argv carries no useful semantic for a classifier; shell-injection markers are deterministically regex-detectable.

For every frame:

```
              ┌────────────────────┐
              │  candidate filter  │  drop pings, list_tools, …
              └─────────┬──────────┘     and frames where there is
                        │                 nothing to inspect
                        ▼
              ┌────────────────────┐
              │   RulesDetector    │  ≤5 ms p95
              └─────────┬──────────┘
                        │ rules_score, hits
                        ▼
        ┌─────  short-circuit?  ──────┐
        │ if rules_score ≥ 0.9        │ → take rules verdict, skip LLM
        │                             │
        ▼ (s2c & textual & |body| in  │
        ┌────────────────────┐  [50, 100_000] bytes)
        │   LLMDetector      │  ≤150 ms p95 cold, ≤2 ms cache hit
        └─────────┬──────────┘
                  │ classifier ∈ {DATA, INSTRUCTION}
                  ▼
          ┌────────────────────┐
          │  combine(r, l)     │  score = max(rules, classifier)
          └─────────┬──────────┘
                    ▼
              ┌──────────┐
              │  Policy  │  config/policies.yaml
              └────┬─────┘
                   ▼
             { allow | warn | block }
```

### 3. LLM backend and fallback chain

- **Primary:** Ollama at `http://localhost:11434`, model `qwen2.5:3b`, `temperature=0`, `num_predict=5` (we want one word: `DATA` or `INSTRUCTION`).
- **Cache:** SHA256 of the candidate body keyed in a new `classifier_cache` table (see §4). TTL 24 h. Cache lookup is the first thing `LLMDetector` does — it costs ~1 ms and saves 100 ms.
- **Circuit breaker:** 3 consecutive failures (HTTP timeout, connection refused, 5xx, malformed body) → open the circuit for 60 s. While open, every LLM call returns immediately with `classifier=None, reason="circuit_open"`. The cascade reduces to rules-only and warns once in stderr.
- **No Anthropic Haiku tier in v0.2** (deferred to v0.3). Reason: ~250-400 ms round-trip would bust the 200 ms budget; v0.3 will redesign the inspector to call the slow tier asynchronously while forwarding the original — that needs its own ADR.

### 4. Detection storage (schema migration v1 → v2)

We extend the existing `events` table — no new table, no JOINs in the hot reader path:

```sql
ALTER TABLE events ADD COLUMN det_verdict     TEXT;     -- 'PASS' | 'WARN' | 'BLOCK'
ALTER TABLE events ADD COLUMN det_score       REAL;     -- 0.0 – 1.0
ALTER TABLE events ADD COLUMN det_rules       TEXT;     -- JSON array of rule ids that hit
ALTER TABLE events ADD COLUMN det_classifier  TEXT;     -- 'DATA' | 'INSTRUCTION' | NULL
ALTER TABLE events ADD COLUMN det_latency_ms  INTEGER;
ALTER TABLE events ADD COLUMN det_action      TEXT;     -- 'allow' | 'warn' | 'block' | 'rewrite'

CREATE INDEX IF NOT EXISTS idx_events_verdict
    ON events(det_verdict) WHERE det_verdict IS NOT NULL;

INSERT OR REPLACE INTO schema_version(version) VALUES (2);
```

`Storage.open()` reads the current `schema_version` row and runs the migration if `version < SCHEMA_VERSION` (now `2`). The migration is idempotent — `ALTER TABLE ... ADD COLUMN` failing because the column already exists is caught and ignored, so reopening a v2 DB never breaks. `note` from ADR-0003 stays as the free-form human-readable annotation slot ("synthetic", "line_limit_exceeded", etc.); the new `det_*` columns are the structured machine-readable verdict.

A second new table for the classifier cache:

```sql
CREATE TABLE IF NOT EXISTS classifier_cache (
    content_hash  TEXT PRIMARY KEY,            -- SHA256 hex of the inspected body
    classifier    TEXT NOT NULL,               -- 'DATA' | 'INSTRUCTION'
    score         REAL NOT NULL,
    cached_at     TEXT NOT NULL,               -- ISO-8601 UTC
    backend       TEXT NOT NULL DEFAULT 'ollama'
);
CREATE INDEX IF NOT EXISTS idx_classifier_cache_cached_at
    ON classifier_cache(cached_at);
```

### 5. Block strategy on s2c (sanitized content)

When the inspector returns `action=block` for a `tools/call` response, the pump forwards a **sanitized replacement** instead of the original line:

```json
{"jsonrpc":"2.0","id":<orig_id>,"result":{"content":[{"type":"text","text":"[mcp-firewall blocked: prompt injection detected. audit log id=<event_id>]"}],"isError":true}}
```

The original line is preserved verbatim in `events.raw` for forensics; only the bytes leaving the proxy are replaced. The replacement contains no attacker-controlled content — the only variable parts are the JSON-RPC `id` (echoed from the request) and our internal audit log id (a positive integer).

For non-`tools/call` responses (e.g. `resources/read`) we ship a structurally similar replacement using whatever content shape the original had; if we cannot construct one safely, we downgrade `block` to `warn` and log loudly.

For c2s when a request hits a `block` policy, we **never forward to the real server**. The pump synthesises a JSON-RPC error reply back to the client and logs a synthetic event marked `direction=server_to_client, kind=error, det_action=block, note="synthetic-block"`. The synthetic event is the only place where the proxy itself is the JSON-RPC peer.

### 6. Policy engine

`config/policies.yaml` is the user's knob. Schema:

```yaml
# Default action when no rule matches
default: allow

rules:
  - name: block_dangerous_shell
    when:
      direction: client_to_server
      method: "tools/call"
      tool_args_match_any: ["rm -rf", "curl | sh", "base64 -d ", "; sh", "wget "]
    action: block
    message: "shell-injection markers in tool arguments"

  - name: block_high_confidence_injection
    when:
      direction: server_to_client
      detector_score_at_least: 0.85
    action: block

  - name: warn_classifier_says_instruction
    when:
      direction: server_to_client
      classifier: INSTRUCTION
    action: warn
```

Rules are evaluated **top to bottom; first match wins**. The policy is consulted *after* both detectors. It cannot manufacture a verdict — i.e. you cannot block a frame whose detector_score is 0.0 with no `when` clauses. The loader rejects rules that have an empty `when:` AND `action: block`.

### 7. Performance budget

End-to-end inspector budget for s2c `tools/call` results: **<200 ms p95**. Decomposition (fresh path, no cache):

| Step                                    | Budget       |
|-----------------------------------------|--------------|
| Pump read + decode                      | <1 ms        |
| Candidate filter (skip protocol frames) | <0.5 ms      |
| Rules detector                          | ≤5 ms p95    |
| Cache lookup (SQLite)                   | <2 ms        |
| LLM Ollama call (cache miss)            | ≤150 ms p95  |
| Policy decision                         | <0.5 ms      |
| Replacement compose (block path)        | <1 ms        |
| **Sum (cache miss, blocked)**           | **≈160 ms**  |

Cache-hit path: ~10 ms total. Skipped-LLM path (rules short-circuit): ~7 ms total.

Hard timeouts: Ollama HTTP request 1000 ms (after which we count it as a circuit failure and fall back to rules-only for this frame). Total pump-thread latency ceiling 250 ms (sanity guard — anything beyond aborts inspection and lets the original through with `det_verdict=WARN, note="inspection_timeout"`).

c2s frames bypass the LLM entirely → typical c2s latency ≤6 ms.

### 8. Module layout

```
src/mcp_firewall/
├── inspector.py            # orchestrator, returns InspectionResult
├── policy.py               # YAML loader + decision tree
└── detectors/
    ├── __init__.py
    ├── base.py             # Detector protocol, Verdict dataclass
    ├── rules.py            # YAML rule pack loader, regex compilation
    └── llm.py              # Ollama client + cache + circuit breaker

rules/
├── builtin/
│   ├── role_hijack.yaml      # "ignore previous", "you are now"
│   ├── exfiltration.yaml     # "send to <url>", credential markers
│   ├── unicode_tricks.yaml   # zero-width, RTL override, homoglyphs
│   ├── html_injection.yaml   # <!-- hidden instructions -->
│   └── shell_injection.yaml  # c2s rules: 'rm -rf', 'curl | sh', …
└── community/                # gitignored; user drops yaml here

config/
└── policies.yaml             # default policy file (sample, committed)
```

### 9. Configuration integration

`Settings` (in `config.py`) gains a frozen sub-dataclass `DetectorSettings` with `enabled=False` by default. YAML schema extends `config.example.yaml`:

```yaml
detector:
  enabled: false                  # opt-in for v0.2
  rules_dir: "rules/builtin"
  llm:
    enabled: true
    backend: "ollama"
    url: "http://localhost:11434"
    model: "qwen2.5:3b"
    timeout_ms: 1000
    cache_ttl_s: 86400
    circuit_threshold: 3
    circuit_open_s: 60
  policies_file: "config/policies.yaml"
  max_latency_ms: 200
```

CLI gets `--detector / --no-detector` and `--policies <path>` overrides on the `run` command.

### 10. Decisions accepted from interactive review

| # | Decision                                | Rationale                                                                    |
|---|-----------------------------------------|------------------------------------------------------------------------------|
| 1 | Block s2c via sanitized result content  | Preserves JSON-RPC contract; agent sees structured `isError=true` and can recover gracefully without retry-storms. |
| 2 | c2s rules-only, no LLM                  | LLM has nothing useful to say about short argv; cheap shell-injection regex catches the realistic threats at <5 ms. |
| 3 | Defer Anthropic Haiku to v0.3           | 250-400 ms breaks 200 ms budget; redesign needs async-parallel inspection that warrants its own ADR. |
| 4 | Inline `det_*` columns on `events`      | Single-table reads, simple `ALTER TABLE` migration, NULL-safe for pre-detection rows; no JOIN cost in `logs --tail`. |

## Consequences

**Positive**

- Deterministic, audit-log-friendly enforcement gate without changing the MCP wire protocol — Claude Desktop and the underlying server stay oblivious.
- Detector fully off-line if the user wants (Ollama on localhost; no network telemetry).
- Migration is additive and backward compatible: a Week 1 `log.db` opens cleanly under Week 2 code with `version` bumped from 1 to 2.
- Rules-only path keeps c2s latency near Week 1 levels (~6 ms).
- Community can ship rule packs as YAML without touching Python.

**Negative / accepted trade-offs**

- The s2c hot path can now stall up to ~200 ms p95 when the LLM is consulted. The `enabled=false` default protects existing users until they opt in.
- One `SCHEMA_VERSION` bump (1 → 2) adds a code path; covered by `tests/test_storage_migration.py`.
- The cache is unbounded by row count for v0.2; we'll add a janitor (`logs --vacuum classifier_cache`) in v0.3 if the table grows.
- Combining via `score = max(rules, classifier)` is conservative (favours BLOCK over ALLOW) — false-positive risk; users dial it down via policy thresholds.
- The synthetic-block path for c2s makes the proxy briefly impersonate a JSON-RPC peer. We mark such events as `note="synthetic-block"` so they are distinguishable in audit.

## Alternatives considered

- **Async parallel inspection** (forward and inspect simultaneously, send a synthetic abort frame on late BLOCK). Rejected for v0.2 — agents may have already acted on partial result by the time the abort lands, and "abort" has no clean MCP semantic. Deferred to v0.3 alongside Haiku.
- **Separate `detections` table** (1:1 FK to `events.id`). Rejected — every reader query needs a JOIN, and v0.2 has no extensibility need that justifies the cost.
- **JSON blob `detection_json` column.** Flexible but unindexable on common filters (`logs --verdict block`); we'd lose the `idx_events_verdict` partial index.
- **HMAC-signed tool-call replacements.** Overkill for a single-machine desktop tool; deferred to a hypothetical multi-tenant Pro version.
- **WAF-style header marking.** MCP has no header layer at the JSON-RPC level; modifying the body is the only available intercept point.

## Things deliberately NOT in v0.2

- Multi-tenant policies, RBAC, per-tool policy sets beyond YAML matching.
- Streaming partial-frame inspection (we still wait for a complete newline-terminated line).
- Detector self-improvement / online learning from user feedback.
- A web UI for reviewing blocked events (CLI `logs --verdict block` only).
- Rotation / compaction of `events` (carry-over from ADR-0002, addressed by `logs --vacuum`).
- Anthropic Haiku tier (deferred to v0.3 with async-parallel inspection redesign).
- Detection on JSON-RPC `notifications/*` frames — they have no `id` and no return path; we only log them.
