# ADR-0006: Rename from `mcp-firewall` to `bulwark-mcp`

- **Status:** accepted
- **Date:** 2026-05-05
- **Deciders:** @churik

## Context

We were planning to ship the v0.4.0 wheel under the name `mcp-firewall` on PyPI when a check before the trusted-publishing run found that the name was already taken. The existing `mcp-firewall` package belongs to Robert Ressl and ships a different product:

- different architecture (OPA / Rego policies, RBAC, compliance reports);
- different threat model (authorisation gateway for MCP, not prompt-injection detection);
- already on PyPI under <https://pypi.org/project/mcp-firewall/>.

Two projects with the same name and overlapping problem space would confuse every potential user. The discovery happened **before** the public launch, so we have a free move.

## Decision

Rename the project from `mcp-firewall` to **`bulwark-mcp`** before announcing it publicly.

The split:

- **PyPI distribution name:** `bulwark-mcp`
- **Python module / import name:** `bulwark_mcp`
- **CLI command:** `bulwark` (not `bulwark-mcp` — the short word is the entry point)
- **GitHub repository:** `churik5/bulwark-mcp`
- **Tagline (unchanged):** "Open-source firewall for MCP servers — catches indirect prompt injection before it reaches your AI agent"

The product positioning stays the same. Only the name changes.

## Consequences

**Positive**

- Clean PyPI namespace, distinct from Robert Ressl's project. Search results don't conflict.
- The CLI verb is shorter (`bulwark doctor` is easier to type than `mcp-firewall doctor`).
- Project name visually distinguishes us as the prompt-injection focused tool while preserving the MCP suffix that signals the integration target.

**Negative / accepted trade-offs**

- Anyone who pulled v0.4.0 manually (the wheel was never published, only the tag exists) needs to switch. Mitigation: v0.4.1 is the public-launch release; v0.4.0 was effectively a private RC.
- Old git commit messages, audit reports, ADRs (0001–0005) and historical release notes still reference `mcp-firewall`. Rewriting history was rejected — the historical record stays accurate to what the project was called at the time. Only the working tree (current docs, code, CI) carries the new name.
- Environment variables also rename: `MCP_FIREWALL_TELEMETRY` → `BULWARK_TELEMETRY`, `MCP_FIREWALL_DB` → `BULWARK_DB`, etc. No backward compatibility because there are no real users to break (pre-launch).

## Alternatives considered

- **Keep `mcp-firewall` and disambiguate via PyPI suggestion to Robert.** Rejected — even if Robert agreed, having two tools with the same name in the wild remains a UX disaster forever.
- **Pick a different, completely unrelated name.** Rejected — keeping the `-mcp` suffix preserves the audience-level signal ("this works with MCP servers") and search-engine relevance.
- **Defer the rename until v0.5.** Rejected — every day post-launch makes the rename costlier (downloads, blog posts, links). Pre-launch is the right window.

## References

- The other project: <https://pypi.org/project/mcp-firewall/>
- Python packaging name conflict guidance: <https://peps.python.org/pep-0541/>
- Our trusted-publishing flow lives in `.github/workflows/publish.yml` and is updated to point at the new project on PyPI.

## Things deliberately NOT in this rename

- Git commit messages, tags, and historical ADRs / release notes / audit reports — left unchanged. Rewriting history would obscure the audit trail (and rebase the public `main` branch, which we have committed not to do).
- v0.4.0 release notes (`docs/RELEASE-v0.4.0.md`) — historical artefact under the prior name. v0.4.1 is the first release under `bulwark-mcp`.
