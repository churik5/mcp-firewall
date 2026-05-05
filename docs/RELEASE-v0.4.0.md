# mcp-firewall v0.4.0 — Launch readiness

**Date:** 2026-05-05
**Status:** alpha — opt-in detector, opt-in telemetry, off-by-default posture preserved.

## What this release is for

Three things, in order of importance:

1. **Closes the Week-3 audit backlog.** All six findings are landed: ReDoS guard for community regex, per-id reply synthesis on JSON-RPC batch block, health endpoint slowloris fix, stats JSON size cap, `/health` TTL cache, cross-script homoglyph detection. Each has a regression test; full report in [`docs/AUDIT-REPORT-week4.md`](AUDIT-REPORT-week4.md).
2. **Ships `doctor` and `benchmark`.** Two CLI subcommands that answer the two questions every new user has on day one — "is my install set up correctly?" and "is the proxy fast enough for my traffic?".
3. **Wires the launch infrastructure.** PyPI trusted publishing, test.pypi smoke flow, auto release notes from CHANGELOG, label sync, auto-labeling, welcome bot, stale closer. All workflows opt-out via repo variable so the maintainer can disable any of them per-release.

The headline numbers: **221 tests** (up from 203), **8 GitHub workflows** (up from 1), **two new CLI subcommands**, **0 new runtime dependencies**.

## What's new

### CLI

```bash
mcp-firewall doctor                  # 4 checks, exit 0/1/2 by worst status
mcp-firewall benchmark -n 200        # rules + cache-hit + end-to-end p50/p95/p99
mcp-firewall benchmark --json        # → still TODO; for now use stats --json
```

### Detection improvements (audit-fix harvest)

| Threat surface that v0.3 missed                                | v0.4 fix                                                       |
|----------------------------------------------------------------|----------------------------------------------------------------|
| Community-contributed regex with catastrophic backtracking     | `lint --strict` static + timed probe rejects ReDoS patterns    |
| Batch JSON-RPC frame: client receives 1 reply for N requests   | per-id reply array; benign siblings get `batch_aborted` errors |
| Hostile localhost peer holds `/health` open indefinitely       | per-connection 5 s `wait_for`; `StreamReader limit=8 KiB`      |
| Corrupted `det_rules` row stalls stats query CPU               | 64 KiB per-row size cap on `json.loads`                        |
| `/health` runs full table SCAN on every probe                  | 1 s TTL snapshot cache under `asyncio.Lock`                    |
| Cyrillic / Greek look-alikes for Latin letters bypass detection| `_HOMOGLYPHS` table folds ~40 high-impact chars during scan    |

### GitHub Actions

| Workflow            | Trigger                  | What it does                                                                 |
|---------------------|--------------------------|------------------------------------------------------------------------------|
| `publish.yml`       | tag push (`v*`)          | Build wheel + sdist; trusted-publish to PyPI; verify tag matches pyproject.  |
| `test-publish.yml`  | manual                   | Build + publish to test.pypi.org; smoke-install from the test index.         |
| `release.yml`       | tag push (`v*`)          | Extract the `[X.Y.Z]` section from CHANGELOG.md; post a GitHub release.      |
| `sync-labels.yml`   | push to `.github/labels.yml` | Apply repo labels via `crazy-max/ghaction-github-labeler`.                |
| `auto-label.yml`    | issue opened/edited      | Keyword-based labels: `[RULE]` → rule-pack, `[BUG]` → bug, etc.              |
| `welcome.yml`       | first-time issue / PR    | Maintainer-voice greeting; pointers to `doctor` and `CONTRIBUTING.md`.       |
| `stale.yml`         | daily cron               | Mark inactive issues / PRs stale at 83 d, close at 90 d.                     |

Each one is gated by `vars.MCP_FIREWALL_DISABLE_<NAME>=true` so disabling one doesn't require editing the workflow file.

### Documentation

- [`docs/FAQ.md`](FAQ.md) — full 10-question FAQ. README inlines the top three.
- [`docs/PERFORMANCE.md`](PERFORMANCE.md) — measured numbers + community-data table. Run `mcp-firewall benchmark` and PR a row.
- [`docs/RELEASING.md`](RELEASING.md) — release procedure. Trusted publishing means no token in the repo.
- README hybrid rewrite — radical voice on hero / problem statement / inline FAQ; light polish on technical sections.

## Test coverage

`pytest tests/` jumps from **203 cases (v0.3)** to **221 cases (v0.4)**, all green. New test files:

- `tests/test_doctor.py` (13 cases) — Python check, Ollama mock, DB writability, rules + policy validation.

Existing files extended:

- `tests/test_lint.py` — `+1` ReDoS detection.
- `tests/test_proxy_block.py` — `+2` batch per-id reply array.
- `tests/test_detectors_rules.py` — `+2` Cyrillic / Greek homoglyph fixtures.

## Compatibility

- Python ≥ 3.11.
- AGPL-3.0-or-later.
- **No new runtime dependencies.** All four new modules (`doctor.py`, `benchmark.py`, plus the workflow YAMLs) reuse existing deps.
- Detector / telemetry / health endpoint stay **off by default**. Existing v0.3 users see no behavioural change unless they opt in.

## Migrating from v0.3.0

1. `pip install -U mcp-firewall` (once published — the trusted-publishing workflow does the upload on tag push).
2. Existing `data/log.db` opens unchanged; schema stays at v2.
3. New CLI commands available immediately:
   ```bash
   mcp-firewall doctor
   mcp-firewall benchmark
   ```
4. Telemetry + health endpoint flags from v0.3 work identically — no env-var or config-key changes.

## Known limitations (v0.5 backlog)

- HTTP/SSE transport (ADR-0006 territory).
- Community rules repository (`mcp-firewall/rules-community`).
- Viewer filters in `mcp-firewall logs` (search by rule id, by trace id).
- Anthropic Haiku fallback tier for the LLM classifier (carried over from v0.2 → v0.3 → now v0.5).
- Full Unicode `confusables.txt` ship — current `_HOMOGLYPHS` table is hand-picked.

Tracked under [`docs/AUDIT-REPORT-week4.md`](AUDIT-REPORT-week4.md) §"Recommended next steps".

## Acknowledgements

The Week-4 audit-fix harvest closes findings surfaced by the Week-3 adversarial review. Threat-model framing remains in ADR-0004 (detection layer) and ADR-0005 (observability + telemetry privacy).

Rule-pack signatures continue to be sourced from public corpora — see [`docs/THREATS.md`](THREATS.md) for the per-rule provenance table. Community rule contributions follow the promotion ladder in [`CONTRIBUTING.md`](../CONTRIBUTING.md).
