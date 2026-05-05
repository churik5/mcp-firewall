# Security policy

## Reporting a vulnerability

**Do not open a public GitHub issue.** Instead, report security vulnerabilities through GitHub's private Security Advisories flow:

> https://github.com/churik5/bulwark-mcp/security/advisories/new

The advisory is private to the maintainer and the reporter until a fix lands. We will:

1. Acknowledge receipt within 72 h.
2. Confirm or dispute the issue and assign a severity within 7 days.
3. For confirmed issues, ship a fix and a coordinated public disclosure within 30 days for high/critical findings, 90 days for medium, on a best-effort basis for low.

If you do not receive an acknowledgement within 72 h, you may open a *generic* GitHub issue saying "I am waiting on a security advisory response" — please do not include the vulnerability details in that public issue.

## Scope

In scope:

- The proxy itself (`bulwark run`).
- Detection-layer bypass classes that could let attacker-controlled content reach an agent despite a `block` policy.
- Audit-log integrity (forensic preservation, schema migrations).
- Local-data-at-rest concerns in the SQLite log.
- Telemetry payload contents (does anything sensitive leak?).

Explicitly out of scope:

- Vulnerabilities in third-party MCP servers we proxy. Report those upstream.
- Vulnerabilities in Ollama or any LLM model. Report those upstream.
- "An attacker who already has shell access on the user's machine can read `data/log.db`." — we agree, and we don't claim host-level isolation.
- Theoretical bypass classes without a concrete PoC. We're happy to discuss those in a public issue.

## Threat model summary

The full threat model lives in [`docs/adr/0004-detection-layer-architecture.md`](docs/adr/0004-detection-layer-architecture.md). Briefly:

- The attacker controls tool-result content flowing from an MCP server back to the agent.
- The proxy must never crash on hostile input.
- Operator-authored YAML policies must not silently relax the default policy through typos or unknown clauses (validated at load time as of v0.3).
- Telemetry, when opted in, must not leak rule names, method names, server commands, or any traffic content.

## What is NOT a vulnerability

- A rule that catches a benign-looking string. Open a normal GitHub issue with the false-positive example; we'll tighten the regex.
- The detection layer missing a sufficiently obfuscated payload (homoglyph, deeply-nested injection, language we don't normalise yet). These are documented limitations in `docs/THREATS.md` §"Limitations". A PR with a fixing rule pack is welcome.

## Acknowledgements

Researchers who report a confirmed issue under this policy are credited in the corresponding GitHub Security Advisory and in the changelog (with their consent).
