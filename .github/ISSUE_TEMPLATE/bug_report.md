---
name: Bug report
about: Report something that isn't working as expected
title: '[BUG] '
labels: bug
assignees: ''
---

## Description

A clear and concise description of what's broken.

## Reproduction steps

Minimal steps to reproduce the issue:

1. Set up `bulwark-mcp` like this: ...
2. Configure the MCP server: ...
3. Run this command: ...
4. Observe ...

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include error messages, stack traces, or unexpected output.

## Environment

- bulwark-mcp version: <!-- run `bulwark --version` -->
- Python version: <!-- run `python --version` -->
- Operating system and version: <!-- e.g. macOS 14.5, Ubuntu 22.04 -->
- MCP server you were using: <!-- e.g. filesystem, github, brave-search -->
- Detection mode: <!-- rules-only / rules+llm / off -->
- Ollama version (if relevant): <!-- run `ollama --version` -->

## Logs

Paste relevant output from the audit log:
bulwark logs --tail 20 --json

If the bug is about a specific event, include its full row from `--json` output.

## Additional context

- Configuration file (redact any secrets): ...
- Custom rules in use: ...
- Anything else that might be relevant.

## Pre-flight checklist

- [ ] I'm using the latest released version (`pip install -U bulwark-mcp`)
- [ ] I've checked the [existing issues](https://github.com/churik5/bulwark-mcp/issues) for duplicates
- [ ] I've redacted any sensitive information from logs and configuration
- [ ] This is **not** a security vulnerability (those go through [SECURITY.md](../../SECURITY.md))
