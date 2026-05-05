"""Tests for the YAML policy engine (ADR-0004 §6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bulwark_mcp.policy import Policy, PolicyDecision

# ---------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------


class TestPolicyLoader:
    def test_loads_default_only_policy(self, tmp_path: Path) -> None:
        path = tmp_path / "p.yaml"
        path.write_text("default: warn\nrules: []\n", encoding="utf-8")
        policy = Policy.from_file(path)
        assert policy.default == "warn"
        assert len(policy) == 0

    def test_rejects_invalid_default(self) -> None:
        with pytest.raises(ValueError, match="invalid default"):
            Policy.from_dict({"default": "explode"})

    def test_rejects_block_with_empty_when(self) -> None:
        with pytest.raises(ValueError, match="cannot use 'block' with an empty"):
            Policy.from_dict(
                {
                    "rules": [{"name": "kill_all", "when": {}, "action": "block"}],
                }
            )

    def test_rejects_invalid_action(self) -> None:
        with pytest.raises(ValueError, match="invalid action"):
            Policy.from_dict(
                {
                    "rules": [
                        {
                            "name": "x",
                            "when": {"direction": "client_to_server"},
                            "action": "kill",
                        }
                    ]
                }
            )

    def test_rejects_duplicate_rule_names(self) -> None:
        with pytest.raises(ValueError, match="duplicate rule name"):
            Policy.from_dict(
                {
                    "rules": [
                        {"name": "r", "when": {"direction": "server_to_client"}, "action": "warn"},
                        {"name": "r", "when": {"direction": "client_to_server"}, "action": "warn"},
                    ]
                }
            )

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            Policy.from_file(tmp_path / "nope.yaml")

    def test_rejects_unknown_when_keys(self) -> None:
        # Audit finding: a typo'd or unsupported `when:` key must not silently
        # pass — otherwise an empty filter would match every frame.
        with pytest.raises(ValueError, match="unknown 'when' keys"):
            Policy.from_dict(
                {
                    "rules": [
                        {
                            "name": "typo",
                            "when": {"directiom": "server_to_client"},  # typo'd
                            "action": "warn",
                        }
                    ]
                }
            )


# ---------------------------------------------------------------------
# Decision matching
# ---------------------------------------------------------------------


def _decide(
    policy: Policy,
    *,
    direction: str = "server_to_client",
    method: str | None = None,
    score: float = 0.0,
    classifier: str | None = None,
    rules_hit: tuple[str, ...] = (),
    raw: str = "",
) -> PolicyDecision:
    return policy.decide(
        direction=direction,  # type: ignore[arg-type]
        method=method,
        score=score,
        classifier=classifier,  # type: ignore[arg-type]
        rules_hit=rules_hit,
        raw=raw,
    )


class TestDecideClauses:
    def test_no_match_falls_back_to_default(self) -> None:
        policy = Policy.from_dict({"default": "warn", "rules": []})
        decision = _decide(policy)
        assert decision.action == "warn"
        assert decision.matched_rule is None

    def test_first_match_wins(self) -> None:
        policy = Policy.from_dict(
            {
                "default": "allow",
                "rules": [
                    {
                        "name": "warn_first",
                        "when": {"classifier": "INSTRUCTION"},
                        "action": "warn",
                    },
                    {
                        "name": "block_high",
                        "when": {"detector_score_at_least": 0.5},
                        "action": "block",
                    },
                ],
            }
        )
        decision = _decide(policy, classifier="INSTRUCTION", score=0.95)
        assert decision.matched_rule == "warn_first"
        assert decision.action == "warn"

    def test_direction_clause(self) -> None:
        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "name": "block_c2s_shell",
                        "when": {"direction": "client_to_server"},
                        "action": "block",
                    }
                ]
            }
        )
        # c2s matches
        d = _decide(policy, direction="client_to_server")
        assert d.action == "block"
        # s2c does not match
        d = _decide(policy, direction="server_to_client")
        assert d.action == "allow"  # default

    def test_method_clause(self) -> None:
        policy = Policy.from_dict(
            {"rules": [{"name": "tcall", "when": {"method": "tools/call"}, "action": "warn"}]}
        )
        assert _decide(policy, method="tools/call").action == "warn"
        assert _decide(policy, method="ping").action == "allow"

    def test_score_threshold_clause(self) -> None:
        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "name": "high",
                        "when": {"detector_score_at_least": 0.85},
                        "action": "block",
                    }
                ]
            }
        )
        assert _decide(policy, score=0.84).action == "allow"  # default
        assert _decide(policy, score=0.85).action == "block"
        assert _decide(policy, score=0.99).action == "block"

    def test_tool_args_match_any_substring(self) -> None:
        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "name": "shell_block",
                        "when": {
                            "direction": "client_to_server",
                            "method": "tools/call",
                            "tool_args_match_any": ["rm -rf", "curl | sh"],
                        },
                        "action": "block",
                    }
                ]
            }
        )
        # Hit
        d = _decide(
            policy,
            direction="client_to_server",
            method="tools/call",
            raw='{"params":{"args":["rm -rf /tmp"]}}',
        )
        assert d.action == "block"
        # Miss (no marker substring)
        d = _decide(
            policy,
            direction="client_to_server",
            method="tools/call",
            raw='{"params":{"args":["ls /"]}}',
        )
        assert d.action == "allow"

    def test_rules_hit_any_clause(self) -> None:
        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "name": "hijack_or_exfil",
                        "when": {
                            "rules_hit_any": [
                                "role_hijack.ignore_previous",
                                "exfil.send_to_url",
                            ]
                        },
                        "action": "block",
                    }
                ]
            }
        )
        assert _decide(policy, rules_hit=("role_hijack.ignore_previous",)).action == "block"
        assert _decide(policy, rules_hit=("unicode.zero_width_run",)).action == "allow"

    def test_and_semantics_across_clauses(self) -> None:
        policy = Policy.from_dict(
            {
                "rules": [
                    {
                        "name": "narrow",
                        "when": {
                            "direction": "server_to_client",
                            "classifier": "INSTRUCTION",
                            "detector_score_at_least": 0.5,
                        },
                        "action": "block",
                    }
                ]
            }
        )
        # All three must match
        assert (
            _decide(
                policy,
                direction="server_to_client",
                classifier="INSTRUCTION",
                score=0.6,
            ).action
            == "block"
        )
        # Drop classifier — no match.
        assert (
            _decide(
                policy,
                direction="server_to_client",
                classifier=None,
                score=0.99,
            ).action
            == "allow"
        )
