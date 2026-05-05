# FAQ

The questions I get most often. Open an issue if yours isn't here.

## Why not just use Lakera, Cloudflare AI Gateway, or Prompt Armor?

Different threat model. Those products sit in front of an LLM API and inspect the chat completion request as a whole. `bulwark-mcp` sits in front of an MCP *server* and inspects the JSON-RPC frame the agent reads as data. The two layers don't compete; you can run both. The reason this exists separately:

- **Self-hosted by default.** No frame leaves your machine unless you opt in to telemetry, and the telemetry payload doesn't carry traffic content. Some teams can't ship tool-result text to a third party for compliance reasons.
- **Audit log is local SQLite.** Forensics for a missed attack means `sqlite3 data/log.db`, not a vendor portal.
- **Rule packs are YAML you can read.** No "trust the magic". You can add a rule for your own corpus in five minutes.

If a vendor solution fits your team better, use it. If you also want a tail-end safety net that runs entirely on the user's machine, add this.

## Does this work without Ollama?

Yes. The detector has two layers: a regex rules engine that always runs (rules ship inside the package, ~25 of them, costs <5 ms p95), and an optional LLM classifier that talks to Ollama. With `--detector` and no Ollama, you get rules-only mode. The circuit breaker notices that Ollama isn't reachable, opens for 60 seconds, and the proxy keeps moving. You'll see `det_classifier=NULL note=circuit_open` in the audit log.

If you do run Ollama, the default model is `qwen2.5:3b` (~2 GB on disk). Any model that responds to `/api/generate` with one of `DATA` or `INSTRUCTION` works; we just chose qwen2.5 because it's fast on Apple Silicon and small enough to keep memory pressure low.

## What MCP servers are supported?

The proxy is server-agnostic — it speaks JSON-RPC over stdio, which is what the MCP spec requires. So in principle, anything that talks MCP works.

We ship integration tests for `github`, `brave-search`, and `postgres`. See [`docs/INTEGRATIONS.md`](INTEGRATIONS.md) for what each test asserts and the per-server config snippet. If you've used `bulwark-mcp` with a server we don't have tests for, a PR adding fixtures + a smoke/benign/attack test trio is the most welcome contribution today.

The only real compatibility constraint: the server must speak newline-delimited JSON-RPC on stdio. HTTP/SSE transport is on the roadmap (ADR-0006 territory) but not yet shipped.

## How does the LLM classifier protect privacy?

The classifier is a local Ollama instance by default — your tool result content never leaves localhost.

If you set `BULWARK_TELEMETRY=true`, the proxy starts shipping a daily anonymous payload to a maintainer-run endpoint. That payload contains:

- `version`, `platform` (linux/darwin), `python_version` — bucketed.
- `installation_id` (UUID, regenerated when you delete `data/installation_id`).
- Four integer event counts (total, blocked, warned, passed) and `days_active`.

It does not contain rule names, method names, server commands, IPs, hostnames, or anything from a tool result. Every payload is appended verbatim to `data/telemetry.log` *before* the HTTP call, so you can `cat` the log and audit what's actually sent. Full schema: [`docs/OBSERVABILITY.md`](OBSERVABILITY.md).

To disable mid-flight: unset the env var, or set `BULWARK_TELEMETRY_URL=disabled` to keep the local log but skip the HTTP call.

## Can I write custom rules?

Yes. A rule is a YAML entry like this:

```yaml
rules:
  - id: namespace.snake_case_id
    description: "What it catches, in one sentence."
    pattern: '<your-regex-here>'    # see src/bulwark_mcp/rules/builtin/ for live examples
    score: 0.85
    apply_to: [server_to_client]
    source: "https://link-to-source"
```

Drop a `.yaml` file under `rules/community/` (gitignored — you control the path), pass `--rules-dir <your-dir>` to the proxy, and the rules engine picks it up alongside the built-in pack.

Validate before shipping:

```bash
bulwark rules lint <file>           # basic checks
bulwark rules lint --strict <file>  # quality gate for built-in promotion
```

The `--strict` mode is documented in [`CONTRIBUTING.md`](../CONTRIBUTING.md). Required for built-in promotion, optional for community packs.

## What's the performance overhead?

With detector off (`--no-detector`, the default): under 5 ms p95 per JSON-RPC frame. The proxy is essentially `cat` plus an audit-log queue.

With detector on and rules-only: ~5–10 ms p95. The three-pass scan over ~25 rules is cheap.

With detector on and the LLM classifier engaged: cache hit is ~10 ms; cache miss against a warm `qwen2.5:3b` is 140–180 ms p50 on Apple Silicon (M-series). Cold model load on the very first frame is 1–2 s — the inspector's hard guard catches that and downgrades the verdict to WARN so the pump never stalls beyond 250 ms.

Numbers in [`docs/PERFORMANCE.md`](PERFORMANCE.md). To get baseline numbers on your machine: `bulwark benchmark`.

## Is this production-ready?

Depends what production means.

The proxy and audit log have been running on my own dev machine since v0.1.0. The detector is `0.x` and defaults to off; nothing about the current shape will surprise a deployment that hasn't opted in. The schema (`schema_version=2`) supports forward migration; we won't break a v0.4 audit log going into v0.5.

What's stable: the proxy, the audit log, the rule-pack format, the JSON output of `stats` (versioned at `schema_version: 1`).

What might change in v0.5: the policy DSL may gain new `when:` clauses, the LLM-classifier prompt may move to a chat-format API. Both will keep backward compatibility on the YAML side. Watch [`CHANGELOG.md`](../CHANGELOG.md).

For commercial use, AGPL means you can run it inside your company without restriction. Hosting it as a service for paying users requires either contributing your modifications back or buying a commercial license — talk to me first.

## How do I report a false positive?

Open a GitHub issue with:

- The input that triggered the rule (`bulwark logs --tail 5` shows the original `raw` column).
- The rule id (same row).
- What you expected (PASS / WARN, with reasoning).

If the rule is in `src/bulwark_mcp/rules/builtin/`, I'll tighten the regex. If it's a community pack, I'll ping the original author on the issue. Either way, the fix usually ships in the next patch release.

If you can include a benign example of the same general shape that *should* still be caught, that's gold — it lets me write a regression test in the same PR.

## What's on the roadmap?

Short version, full version in [`README.md`](../README.md#roadmap):

- v0.4: launch (PyPI publish, GitHub workflows, README polish — this release).
- v0.5: HTTP/SSE transport, community rules repository, viewer filters in `bulwark logs`.
- v0.6+: Pro tier — hosted log shipping, threat-feed sync, alerts to Slack/Discord/Telegram.

The Pro tier is additive on top of the open-source core; the firewall itself stays AGPL forever.

## Can I run this in production / for commercial use?

Yes. AGPL-3.0 covers internal commercial deployment with no restrictions — you're using it on your own machines, that's fine. The license clause that catches people is the "service over a network" trigger: if you wrap `bulwark-mcp` in a hosted product that other people pay to use, you have to make your modifications available to them under AGPL, or buy a commercial license from me.

For self-hosted internal tools, agent platforms running inside one company, or an MCP gateway you ship to your own employees: AGPL is fine, no extra paperwork.

For a SaaS product where the firewall is a feature you sell: open a discussion, we'll work something out.
