# bulwark-mcp v0.4.1 — Renamed from `mcp-firewall`

**Date:** 2026-05-05
**Status:** alpha — same code as v0.4.0 with a new name.

## What this release is

A name change. `mcp-firewall` was already taken on PyPI by an unrelated project (Robert Ressl's OPA / Rego authorisation gateway, also for MCP). We discovered the conflict before the public launch, so we renamed before any wheel hit PyPI.

The product, the threat model, and the code all stay the same. Only the labels move.

## What changed

| Surface                  | Was                          | Is                            |
|--------------------------|------------------------------|-------------------------------|
| **PyPI distribution**    | `mcp-firewall`               | `bulwark-mcp`                 |
| **CLI command**          | `mcp-firewall …`             | `bulwark …`                   |
| **Python module**        | `import mcp_firewall`        | `import bulwark_mcp`          |
| **GitHub repository**    | `churik5/mcp-firewall`       | `churik5/bulwark-mcp`         |
| **Telemetry env vars**   | `MCP_FIREWALL_TELEMETRY*`    | `BULWARK_TELEMETRY*`          |
| **Override env vars**    | `MCP_FIREWALL_DB`, `_CONFIG` | `BULWARK_DB`, `_CONFIG`       |

The tagline is unchanged: **"Open-source firewall for MCP servers — catches indirect prompt injection before it reaches your AI agent."**

## Why

The full rationale is in [`docs/adr/0006-rename-from-mcp-firewall-to-bulwark-mcp.md`](adr/0006-rename-from-mcp-firewall-to-bulwark-mcp.md). Briefly: two tools with the same name in the same niche is a UX disaster forever, and we caught it before the wheel went public. Pre-launch is the right window.

## Migrating from v0.4.0

Anyone who pulled the v0.4.0 tag manually:

```bash
pip uninstall mcp-firewall            # remove the old install
pip install bulwark-mcp                # once published

# CLI: replace `mcp-firewall <subcommand>` with `bulwark <subcommand>` everywhere.
mcp-firewall doctor      →  bulwark doctor
mcp-firewall run --…     →  bulwark run --…
mcp-firewall stats       →  bulwark stats

# Env vars: rename in your shell rc / systemd unit / Claude Desktop config.
MCP_FIREWALL_TELEMETRY=true   →  BULWARK_TELEMETRY=true
MCP_FIREWALL_TELEMETRY_URL    →  BULWARK_TELEMETRY_URL
MCP_FIREWALL_DB               →  BULWARK_DB
MCP_FIREWALL_CONFIG           →  BULWARK_CONFIG
```

Existing `data/log.db` opens unchanged — schema stays at v2.

The Claude Desktop config snippet:

```json
{
  "mcpServers": {
    "filesystem-monitored": {
      "command": "/absolute/path/to/.venv/bin/bulwark",
      "args": ["run", "--server", "..."]
    }
  }
}
```

## What did NOT change

- No functional changes. Same code, same behaviour.
- Same versioned schemas (`schema_version=2` in the DB; `schema_version=1` in stats / telemetry payloads).
- Same threat model. The detection cascade, policy engine, audit log, telemetry contract, all work identically.
- Old git history stays under the prior name. ADRs 0001–0005 and the v0.1.0–v0.4.0 release notes are historical artefacts; we did not rewrite them.

## What's next

Public launch (HN, r/LocalLLaMA, r/selfhosted, X) — that's Week 5. v0.5 is then community rules repo (`bulwark-mcp/rules-community`), HTTP/SSE transport, viewer filters in `bulwark logs`. The v0.5 backlog is in [`docs/AUDIT-REPORT-week4.md`](AUDIT-REPORT-week4.md) §"Recommended next steps".
