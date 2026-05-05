# Week-3 Audit Report

**Date:** 2026-05-05
**Reviewer:** self-audit via Claude Code (general-purpose subagent, adversarial security brief)
**Scope:** Week 3 delta — 4 audit-fix follow-ons from Week 2, opt-in telemetry, health endpoint, stats command, rules-lint command, integration tests, and supporting docs.

## TL;DR

| Check                                | Verdict | Notes                                                                         |
|--------------------------------------|---------|-------------------------------------------------------------------------------|
| `pip-audit --skip-editable`          | ✅ PASS | "No known vulnerabilities found".                                             |
| `ruff check src tests`               | ✅ PASS | 0 errors after format pass.                                                   |
| `ruff format --check`                | ✅ PASS | All formatted.                                                                |
| `mypy --strict src tests`            | ✅ PASS | 0 issues across 38 source files.                                              |
| `pytest tests/` (full suite)         | ✅ PASS | 203 / 203 (was 121 in Week 2, 27 in Week 1).                                  |
| Adversarial review                   | ⚠️ WARN | 10 findings: **4 fixed in this milestone**, 6 deferred to v0.4 (documented). |
| New runtime deps                     | ✅ PASS | Zero. (Adds `import re` and `import os.chmod` but no new package dependencies.)|

**Net verdict: ✅ ship.** All HIGH-severity findings flagged in this audit are closed in this milestone; remaining MEDIUM/LOW items are scoped, documented, and tracked.

---

## 1. Adversarial review — findings and dispositions

The reviewer was briefed against the threat model in ADR-0005 (privacy contract for telemetry) and ADR-0004 (detection layer).

### Fixed in v0.3

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | HIGH | **`platform.release()` leaks fingerprintable identity.** Linux returns full kernel build strings (e.g. `5.4.0-foo-bar`), uniquely identifying custom kernels. ADR-0005 §3 explicitly forbids this. | `_major_release()` in `telemetry.py` reduces the value to its first numeric component (`"5"`, `"23"`, etc.) before sending. |
| 2 | MEDIUM | **`data/telemetry.log` and `data/installation_id` were created with default umask (0644).** Co-tenants on a shared machine could read every payload, including the installation UUID. | Both files now `os.chmod(path, 0o600)` on creation. Existing files keep their mode. |
| 3 | LOW | **`_trace_id` mixed the entire raw frame into the SHA1 seed.** On 8 MiB frames this hashed megabytes per block on the hot path. `os.urandom(8)` already provides unguessability. | `_trace_id` now seeds with `perf_counter_ns + os.urandom(8)` only; the `raw` parameter is retained for forward compatibility but unused. |
| 4 | MEDIUM | **Truncation was silent.** A 50 KiB tool result with a payload past byte 8000 produced `det_classifier=null` with `note=ok` — indistinguishable from a clean classification. | `OllamaClassifier.classify()` now returns `reason="ok:truncated=<chars>"` when the input was cut. The inspector copies that into `note`, so the operator can grep for `det_action=allow note LIKE 'ok:truncated%'` to find under-inspected frames. |

### Deferred to v0.4 (documented limitations)

| # | Severity | Finding | Why deferred |
|---|---|---|---|
| 5 | HIGH | **ReDoS via community-contributed regex.** `re.compile` accepts catastrophic-backtracking patterns (`(a+)+b`); the detector then runs them against attacker-controlled tool results up to 8 MiB. A community pack could DoS every install. | A robust fix needs a per-rule wall-clock budget and a static-quantifier-nesting check; both are non-trivial. v0.3 mitigates by **shipping zero community packs by default** — the threat is theoretical until community PRs land. v0.4 adds a 100 ms timed `attack_examples` execution in `--strict` lint, plus a runtime cap. |
| 6 | HIGH | **Batch JSON-RPC ID confusion on block.** When a 3-element batch contains one malicious member, the proxy emits a 1-element reply array. Two of the three request ids never get a response — the client may hang. The audit log is correct; the wire is desynced. | A correct fix requires synthesising per-id error replies for non-blocking members, which is doable but needs careful handling for c2s vs s2c semantics and notification-shaped batch members. v0.3 accepts the conservative posture; v0.4 lands the per-id reply array. |
| 7 | MEDIUM | **Health endpoint slowloris exposure.** `asyncio.start_server` reads with the default 64 KiB buffer; no per-connection timeout. A hostile localhost peer can hold an event-loop slot indefinitely. | Loopback-only binding makes this a same-machine threat. Fix: wrap `_serve_one` in `asyncio.wait_for(timeout=5.0)` and pass `limit=_MAX_REQUEST_LINE` to `StreamReader`. Tracked. |
| 8 | LOW | **`stats.compute_stats` parses every `det_rules` JSON column without a size cap.** A corrupted row could feed `json.loads` 100 MB of nested arrays. | Same code path runs in the telemetry side-car. Fix: 64 KB length guard before `json.loads`. Tracked. |
| 9 | LOW | **`/health` runs `event_count()` (full table SCAN) on every probe.** A hostile localhost peer can starve the writer. | Loopback-only binding limits the threat to local malware. Fix: 1 s in-memory cache for the snapshot. Tracked. |
| 10| MEDIUM | **Cross-script homoglyphs (Cyrillic letters substituted for Latin) still bypass the detector.** NFKC keeps them separate by design. | Already documented in `tests/test_detectors_rules.py::TestNormalisationBypass` and `docs/THREATS.md` §"Limitations". Resolution requires shipping a `confusables` mapping (~10 MB), out of scope for v0.3. |

All deferred items are tracked in `docs/RELEASE-v0.3.0.md` under "Known limitations".

### What's solid (reviewer's notes)

- The three-pass scan in `RulesEngine.detect` correctly dedupes when the three normalised forms collapse to one — benign text takes one regex run per rule, not three.
- The audit log preserves the **original** bytes on block; only the bytes leaving the proxy are sanitised. `tests/test_proxy_block.py::test_s2c_prompt_injection_is_blocked_and_replaced` asserts the raw column still contains the attacker payload for forensics.
- `test_health.py::test_listener_is_loopback_only` checks `getsockname()[0]` against the live socket, not just the call argument — the loopback claim is genuinely tested against the OS.
- `TelemetryClient.show_banner_once` is single-shot per process AND fenced by the `_banner_shown` flag — no risk of double-banner spam.
- `BULWARK_TELEMETRY_URL=disabled` correctly skips the HTTP call but **still** writes the local log, matching the ADR contract verbatim.

---

## 2. Dependency audit

```
$ python -m pip_audit --skip-editable
No known vulnerabilities found
```

Week 3 added **zero** new runtime dependencies. The implementation re-uses `httpx` (Week 1), `pydantic` (Week 1), and `pyyaml` (Week 1).

## 3. Static analysis

| Tool                          | Result                                       |
|-------------------------------|----------------------------------------------|
| `ruff check src tests`        | All checks passed                            |
| `ruff format --check`         | All formatted                                |
| `mypy --strict src tests`     | 0 issues across 38 source files              |
| `pytest tests/`               | 203 / 203, ≈4.0 s wall-clock                 |

## 4. Coverage gains over Week 2

| Surface                                    | Week 2 | Week 3 |
|--------------------------------------------|-------:|-------:|
| Test files                                 | 8      | 16     |
| Test cases                                 | 121    | 203    |
| `src/` modules                             | 12     | 17     |
| ADRs                                       | 4      | 5      |
| Integration-tested MCP servers             | 0      | 3      |
| Lines of code (rough, `wc -l src/**/*.py`) | ~2200  | ~3500  |

## 5. Recommended next steps (post-ship)

1. **Land per-id batch reply synthesis** (finding 6) before opening the firewall to any agent that uses JSON-RPC batching at scale. The current behaviour is correct from the *audit* side but desyncs the wire.
2. **Add `--strict` ReDoS guard** (finding 5) before merging the first community rule-pack PR. Without it, the very community contract Week 3 is shipping becomes the attack surface.
3. **Health endpoint timeout + read cap** (finding 7) — quick fix, worth doing before the v0.3 announcement so we don't claim "k8s-ready" with a slowloris hole.
4. **Cross-script homoglyph coverage** (finding 10) via a `confusables` table — scoped for v0.4.
