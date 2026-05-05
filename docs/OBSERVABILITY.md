# Observability

`bulwark-mcp` ships three observability primitives. Two are local-only;
the third (telemetry) is **off by default** and must be opted into per
process via an environment variable. The full architectural intent is
in [`docs/adr/0005-observability-and-telemetry.md`](adr/0005-observability-and-telemetry.md).

## 1. Local stats — `bulwark stats`

A read-only summary of the audit log. Reads `events.det_*` columns,
groups, prints. Never reaches the network.

```bash
bulwark stats                          # last 7d, Rich table
bulwark stats --since 24h              # last 24h
bulwark stats --json                   # pretty JSON
bulwark stats --json --compact         # one-line JSON, for cron
```

JSON shape (`schema_version: 1`):

```json
{
  "schema_version": 1,
  "period_start": "2026-04-28T00:00:00+00:00",
  "period_end":   "2026-05-05T00:00:00+00:00",
  "total_events": 14879,
  "verdicts": {"PASS": 14820, "WARN": 47, "BLOCK": 12},
  "top_rules": [{"id": "<rule-id>", "count": 8}],
  "latency_ms": {"p50": 0.04, "p95": 0.13}
}
```

We commit to never silently changing format-1 fields. New fields can
be added in a non-breaking way.

## 2. Health endpoint — `--health-port N`

When the proxy starts with `--health-port N`, an asyncio listener
binds to **127.0.0.1:N** (loopback only — never a wildcard) and
exposes one route:

```
GET /health → 200 application/json
```

Body:

```json
{
  "status": "ok",
  "version": "0.3.0",
  "uptime_s": 3712.4,
  "events_processed": 14879,
  "last_event_ts": "2026-05-05T08:14:33.211934+00:00"
}
```

There is no authentication and no TLS — the listener is loopback-only
on purpose. If you want it exposed, put it behind a reverse proxy you
trust. Bind failures (port in use, permission denied) log a warning
and disable the endpoint, but do **not** crash the proxy.

Use cases:

- k8s liveness/readiness probes (`httpGet: { path: /health, port: N }`).
- docker `HEALTHCHECK CMD curl -fsS http://127.0.0.1:N/health`.
- supervisord and systemd readiness checks.

## 3. Telemetry — opt-in, anonymous, transparent

### Enabling

```bash
export BULWARK_TELEMETRY=true
bulwark run --server "..."
```

On the first transmission, the proxy writes a multi-line banner to
stderr stating what is sent, where, and how to disable. The banner is
shown once per process.

### Disabling

Unset the env var, or set it to anything other than `true|1|yes|on`
(case-insensitive). Default is **off** — there is no CLI flag and no
config-file flip, by design.

### Endpoint

- Default URL: `https://telemetry.example.com/v1/ingest` (placeholder
  in v0.3.0; replaced before launch).
- Override: `BULWARK_TELEMETRY_URL=https://my-self-hosted.example/v1`.
- **Kill-switch:** `BULWARK_TELEMETRY_URL=disabled` skips the
  HTTP call entirely while still writing the local log — useful for
  offline development or for users who want to inspect what *would*
  be sent without sending it.

### Cadence

- First transmission: **60 seconds** after the proxy starts (debounces
  flapping restarts).
- Then every **24 hours** while the process is alive.
- No persistent queue: if the network is down, that day's data is lost.

### Payload schema (`schema_version: 1`)

```json
{
  "schema_version": 1,
  "installation_id": "8a1b2c…",
  "version": "0.3.0",
  "platform": "darwin",
  "platform_release": "23.0.0",
  "python_version": "3.12",
  "days_active": 14,
  "events_total": 12450,
  "events_blocked": 8,
  "events_warned": 23,
  "events_passed": 12419,
  "detector_enabled": true
}
```

`installation_id` is a random UUID generated on first telemetry-enabled
run and stored in `<db-dir>/installation_id`. We use it only to
deduplicate the same installation hitting the endpoint multiple times
per day. Removing the file resets the identity.

### What we explicitly DO NOT send

- **Rule IDs** and rule pack names — they reveal the user's threat
  model and could fingerprint deployments.
- **Method names**, JSON-RPC ids, `--server` strings, server commands.
- **Audit log contents** (raw, params, results, errors).
- **IP, hostname, MAC, container id, hardware UUID** — anything tying
  the installation to a person or company.
- **Configuration files**, custom rule packs, custom policies — even
  their existence.

If you find a code path that would leak any of the above, please file
a security advisory per [`SECURITY.md`](../SECURITY.md).

### Local log — `data/telemetry.log`

Every payload is written to `<db-dir>/telemetry.log` *before* the HTTP
call. Network errors never erase the log entry. One JSON object per
line:

```json
{"ts": "2026-05-05T08:14:33.211934+00:00", "status": "ok", "payload": {...}}
{"ts": "2026-05-06T08:14:35.111111+00:00", "status": "error:ConnectError", "payload": {...}, "error_message": "..."}
```

Inspect at any time:

```bash
tail -n 5 ~/path/to/data/telemetry.log | jq .
```

### Silent fail on network errors

Telemetry must never block, slow, or crash the proxy. Every HTTP call
is wrapped in a 5 s timeout and a broad `except` that records the
error to the local log and returns. There is no retry.

### Privacy posture summary

- Off by default. Opt-in is per-process and explicit.
- No queue, no buffering — one transmission attempt per day max.
- Local log first; HTTP is best-effort.
- Schema versioned; new fields are additive, never silently changing.
- The maintainer has no way to identify a user from the payload —
  `installation_id` is a self-generated UUID, deletable at will.
