# MCP server integrations

Status of each MCP server we have explicitly tested with `bulwark-mcp`.

| Server | Tested | Detection | Config snippet | Notes |
|---|---|---|---|---|
| `@modelcontextprotocol/server-filesystem` | ✅ Week 1 RUNBOOK e2e + Week 3 audit | role-hijack in file content | `--server "npx -y @modelcontextprotocol/server-filesystem /Users/me/Documents"` | Pin `2025.11.25` until upstream zod-v4 ESM regression is fixed. |
| `github-mcp-server` | ✅ Week 3 fixtures | role-hijack + exfiltration in issue / PR / commit body fields | `--server "npx -y @modelcontextprotocol/server-github"` (set `GITHUB_PERSONAL_ACCESS_TOKEN`) | The headline threat is *attacker-controlled text in issue bodies* that the agent reads when calling `get_issue` / `list_issues`. |
| `brave-search-mcp` | ✅ Week 3 fixtures | snippet poisoning (search-result text injects instructions) | `--server "npx -y @modelcontextprotocol/server-brave-search"` (set `BRAVE_API_KEY`) | Search results return third-party page content; assume hostile. |
| `postgres-mcp` | ✅ Week 3 fixtures | stored injection (TEXT columns containing role-hijack) | `--server "npx -y @modelcontextprotocol/server-postgres postgresql://..."` | An attacker who can write a row with TEXT content can target a future agent run. |
| `slack-mcp` | ⚠️ Untested | (planned: Week 4) | `--server "..."` | Threats: link unfurls, channel topic, DM contents. |
| `gdrive-mcp` | ⚠️ Untested | (planned: Week 4) | `--server "..."` | Threats: doc body, comments, file metadata. |
| `puppeteer-mcp` | ⚠️ Untested | (planned: Week 5) | `--server "..."` | Threats: page text, alt-text, hidden HTML. |

## What "tested" means

For every ✅ row we ship three integration tests under
`tests/integration/<server>/` that do not contact the real upstream
API:

1. **Smoke** — the server's `initialize` reply round-trips through the
   proxy unchanged.
2. **Benign** — a realistic-shape tool result with no payload passes
   through and gets `det_verdict=PASS`.
3. **Attack** — a realistic-shape tool result containing a known
   prompt-injection class is replaced with a sanitised reply, with
   `det_verdict=BLOCK` in the audit log.

## What we don't test

- **Real-world rate limits, auth flows, paging.** Those are the
  upstream server's job.
- **End-to-end behaviour with a live LLM in the loop.** We test that
  the proxy *delivers* a sanitised reply; what the agent does with
  it is out of scope.
- **Mutating tools** (`create_issue`, `INSERT`, etc.). Detection runs
  but we do not yet have an attacker-controlled write fixture.

## Adding a new server

See [`tests/integration/README.md`](../tests/integration/README.md).
The summary: copy one of the existing `test_<server>.py` files,
write three JSON fixtures (handshake / benign / attack), update the
table above, and open a PR. The fixtures make integration tests
deterministic and offline — never call a real API in CI.

## Filing real-world false positives or misses

Open a GitHub issue with:

- The exact JSON-RPC frame the upstream server sent (please redact
  any credentials or PII first).
- The verdict you saw in the audit log (`bulwark logs --tail 5`).
- The verdict you expected.

That's the single most valuable contribution today. Public PoCs of
prompt-injection in real MCP traffic are still scarce.
