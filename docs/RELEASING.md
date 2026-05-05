# Releasing

This is the procedure for cutting a new release. It's short on purpose.

## One-time setup (already done for the maintainer)

1. **PyPI trusted publisher.** Configure the project on PyPI:
   - Owner: `churik5`
   - Repository: `bulwark-mcp`
   - Workflow filename: `publish.yml`
   - Environment name: `pypi`

   PyPI grants OIDC tokens to that exact tuple, so no `PYPI_TOKEN` ever
   lives in the repo.

2. **test.pypi.org trusted publisher.** Same idea, environment name
   `testpypi`, workflow `test-publish.yml`.

3. **GitHub environments.** Two envs (`pypi`, `testpypi`) created in
   the repo settings. No protection rules — the workflows are gated
   on the tag pattern itself.

## Cutting a release

```bash
# 1. Make sure main is green and the branch is clean.
git checkout main
git pull --ff-only
ruff check . && ruff format --check . && mypy src/ tests/ && pytest -q

# 2. Bump the version. The CHANGELOG section heading must match.
sed -i.bak -E 's/^version = "[^"]*"/version = "0.4.0"/' pyproject.toml && rm pyproject.toml.bak
$EDITOR CHANGELOG.md            # add the [0.4.0] section
$EDITOR docs/RELEASE-v0.4.0.md  # write release notes

# 3. Commit + tag.
git add pyproject.toml CHANGELOG.md docs/RELEASE-v0.4.0.md
git commit -m "feat: complete week N (v0.4.0)"
git tag -s v0.4.0 -m "v0.4.0"

# 4. Push.
git push origin main v0.4.0
```

Two workflows fire on the tag:

- **`publish.yml`** — builds wheel + sdist, verifies that the tag
  matches `pyproject.version`, uploads to PyPI via OIDC.
- **`release.yml`** — extracts the matching `## [0.4.0]` section from
  `CHANGELOG.md` and posts it as a GitHub release.

If either step fails, fix forward — never edit a tag in place. Delete
the bad tag, push a corrected commit, re-tag.

## Pre-release sanity check (optional)

Before tagging for real, run the test.pypi flow:

```
GitHub → Actions → "Publish to test.pypi.org" → Run workflow
  → version_suffix: ".rc1"
```

The workflow rewrites `pyproject.toml` in-place (only on the runner),
publishes `0.4.0rc1` to test.pypi.org, then smoke-installs it from the
test index back into a temp venv and runs `--version`. If that succeeds,
the real tag will too.

## Hotfix releases

If you find a critical bug after a release:

```bash
git checkout main
# fix it
git commit -m "fix(scope): one-liner about the bug"
# bump patch version
sed -i.bak -E 's/^version = "[^"]*"/version = "0.4.1"/' pyproject.toml && rm pyproject.toml.bak
# CHANGELOG: add [0.4.1] section pointing to the fix commit
$EDITOR CHANGELOG.md
git add pyproject.toml CHANGELOG.md && git commit -m "feat: bump 0.4.1"
git tag -s v0.4.1 -m "v0.4.1"
git push origin main v0.4.1
```

Same workflows fire. There is no separate stable branch — every
release ships from `main` head.

## What the workflows verify

`publish.yml` aborts if any of these fail:

- The tag (`v$X.Y.Z`) does not match `pyproject.version`.
- `python -m build` exits non-zero (broken pyproject, missing files).
- The PyPI side rejects the upload (most likely cause: the trusted
  publisher tuple drifted from the workflow filename).

`release.yml` is best-effort — if it can't extract the changelog
section it falls back to "See CHANGELOG.md" and still posts the release.

## Disabling a workflow temporarily

Each workflow respects a repo variable. To skip publishing for one
release without editing files, set
`MCP_FIREWALL_DISABLE_PUBLISH=true` in the repo settings before
pushing the tag. Same pattern for `MCP_FIREWALL_DISABLE_RELEASE`,
`MCP_FIREWALL_DISABLE_TEST_PUBLISH`, etc. Remember to unset it
afterwards.
