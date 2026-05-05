---
name: New detection rule proposal
about: Propose a new rule for the detector
title: '[RULE] '
labels: rule-pack, enhancement
assignees: ''
---

## Attack class

What kind of attack is this? Pick the closest:

- [ ] Role hijack (instruction override, persona change)
- [ ] Data exfiltration (credentials, files, environment leak)
- [ ] Shell injection (command execution via tool args)
- [ ] Unicode obfuscation (homoglyphs, zero-width chars, RTL tricks)
- [ ] HTML/markdown injection (hidden comments, invisible elements)
- [ ] Tool confusion (one tool response triggers another tool)
- [ ] Other — describe below

## What does the attack look like

A canonical example of the attack — the exact string or JSON-RPC frame that should be caught. Redact if needed.

If this is from a real public source — link it (CVE, GitHub issue, blog post, paper). This becomes the `source` field in the rule YAML.

## Why current rules miss it

Have you tested this against current bulwark rules? What happens?

Run: `echo "<your test payload>" | bulwark detect`

Paste the output. If it returns PASS or fires the wrong rule — that's the gap.

## Proposed rule

If you have an idea for the regex or pattern, share it. Use the YAML schema from CONTRIBUTING.md.

If you don't have a regex yet — that's fine. Describe the pattern in words and we'll work on it together.

## False positive concerns

What benign content might accidentally match this pattern?

- Examples of strings that should NOT trigger this rule
- Common scenarios where the attack vocabulary appears legitimately (documentation, tutorials, error messages)

## Direction

Where in the proxy should this rule fire?

- [ ] server_to_client (s2c) — incoming data inspected for hidden instructions (most common)
- [ ] client_to_server (c2s) — outgoing tool calls inspected for dangerous arguments
- [ ] both — applies in either direction

## Tier target

- [ ] community — submit to rules/community/, low bar, lightweight review
- [ ] built-in — aim for rules/builtin/, requires positive + negative tests, source citation, low FPR

## References

Links to public PoCs, related research, similar rules in other tools (garak, promptfoo, Lakera, etc.), threat reports — anything supporting this rule's existence.

## Pre-flight checklist

- [ ] This attack pattern is publicly documented (not a private engagement)
- [ ] I've tested current bulwark-mcp and confirmed it doesn't catch this
- [ ] I've read CONTRIBUTING.md authoring rules section
- [ ] If I'm proposing built-in tier, I'm willing to provide both positive and negative test cases
_*_*_*_*_*
