# Contributing to bulwark-mcp

Thanks for considering a contribution! This document covers what you need to know to make your PR easy to review and merge.

There is **no CLA and no DCO**. The repository is licensed under AGPL-3.0-or-later, and that is the only legal stipulation we make.

## What we welcome most

In rough order of impact:

1. **Real-world prompt-injection PoCs that we currently miss.** Open an issue with a reproduction (a JSON-RPC frame and what should happen). This is the single most valuable contribution today.
2. **Community rule packs.** YAML files describing new attack patterns. See *Authoring rules* below.
3. **MCP server integrations.** Tested compatibility with a server we don't yet cover. See *Integration tests*.
4. **Performance regressions you can demonstrate.** A benchmark and a fix.
5. **Documentation improvements** — typos, clarifications, missing edge cases.

## Setup

```bash
git clone https://github.com/churik5/bulwark-mcp.git
cd bulwark-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Smoke test
pytest -q
ruff check . && ruff format --check . && mypy src/ tests/
```

## Authoring rules

Rule packs are YAML files under `src/bulwark_mcp/rules/builtin/` (shipped with the package) or `rules/community/` (gitignored, user-supplied). Schema:

```yaml
rules:
  - id: namespace.snake_case_id        # unique across all loaded packs
    description: "What this rule catches, in one sentence."
    pattern: '<Python re-compatible regex; flag inline like (?i)>'
    score: 0.0..1.0                    # confidence weight
    apply_to: [server_to_client]       # or [client_to_server], or both
    source: "https://..."              # required: PoC, paper, library reference

    # Optional but RECOMMENDED for built-in promotion:
    severity_tier: experimental        # or 'stable'
    attack_examples:                   # at least one PoC the rule should match
      - "<a complete PoC string from a public source>"
    false_positive_examples:           # benign strings the rule must NOT match
      - "<a benign string that mentions related vocabulary>"
```

### Promotion ladder

We ship two tiers of rules:

- **`rules/community/`** — third-party YAML drops. Lower bar:
  - `bulwark rules lint <file>` (basic mode) must pass.
  - PR description states what attack class the rule targets.
- **`src/bulwark_mcp/rules/builtin/`** — ships with the package, runs by default. Higher bar:
  - `bulwark rules lint --strict <file>` must pass with **zero warnings**.
  - At least **two tests** in the same PR: one positive (the rule fires on the canonical attack) and one false-positive (the rule does *not* fire on a benign string that mentions related vocabulary).
  - `description` is a complete sentence; `source` is a working URL.

Open the PR against `rules/community/` first; once it has been used in the wild and flushed any false positives, anyone (including you) can open a follow-up promoting it to `builtin/`.

## Integration tests

To claim "bulwark-mcp works with `<your-favourite-MCP-server>`", add a directory under `tests/integration/`:

```
tests/integration/<server-name>/
├── README.md           # one paragraph explaining the server
├── fixtures/
│   ├── handshake.json  # initialize + initialized + tools/list reply
│   ├── benign.json     # a normal tool call + result
│   └── attack.json     # a tool result containing a known prompt injection
└── test_<server>.py    # exercises the proxy with the fixtures
```

The point is to never call the real third-party API in tests — fixtures stand in for the server's output. We test that the proxy:

1. Round-trips the protocol shapes the server actually emits.
2. Blocks the attack fixtures (with the default policy).
3. Lets the benign fixtures through (no false positives on real shapes).

## Pull-request workflow

1. Open an issue first if the change is non-trivial. We don't want you to spend time on a PR we'd reject.
2. Branch from `main`. We don't ship long-lived release branches yet.
3. **Conventional Commits** — `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`. CI lints them.
4. **No format-only changes** mixed with logic changes — split them into separate commits if they accidentally land together.
5. **Tests for behaviour, not implementation.** A refactor that leaves the public API unchanged must keep the existing tests passing without modification.
6. CI must be green: ruff, mypy strict, pytest, pip-audit. Local one-liner:
   ```bash
   ruff check . && ruff format --check . && mypy src/ tests/ && pytest -q
   ```
7. Reviewers will leave comments on the PR. We aim for first response within 72 h on weekdays. After feedback, force-pushing your branch is fine and expected.
8. Squash merge is the default; the PR title becomes the squash commit subject.

## What we'll usually decline

- New runtime dependencies. The whole proxy depends on six Python packages today and we want to keep that number small.
- Default-on telemetry / network calls. The privacy posture of a self-hosted firewall is asymmetric — we err on the side of "explicit opt-in only".
- Architectural rewrites that don't reference an existing ADR. If you think the architecture is wrong, open an issue with a draft ADR proposing the change.

## Reporting security issues

**Do not file a GitHub issue for security vulnerabilities.** Use the GitHub Security Advisories flow described in [SECURITY.md](SECURITY.md).

## Code of conduct

We follow [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be kind. The project is small enough that we expect to handle issues in good faith; egregious cases get the standard escalation path.
