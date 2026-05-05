"""YAML-driven policy engine (ADR-0004 §6).

A *policy* is a list of named rules evaluated **top to bottom, first
match wins**. Each rule has a ``when:`` clause (a mapping of facts to
required values) and an ``action`` (``allow`` / ``warn`` / ``block`` /
``rewrite``). Empty ``when:`` paired with ``action: block`` is rejected
at load time — that combination would block every frame, which is
almost never what a user means.

Currently supported ``when:`` clauses
-------------------------------------

- ``direction``               — exact match against ``client_to_server`` or
  ``server_to_client``.
- ``method``                  — exact match against the JSON-RPC method
  (e.g. ``tools/call``).
- ``classifier``              — ``DATA`` or ``INSTRUCTION``.
- ``detector_score_at_least`` — the inspector's combined score must reach
  this float.
- ``tool_args_match_any``     — a list of substrings; any one matched in
  the raw frame triggers.
- ``rules_hit_any``           — a list of rule ids; any one in the rules
  detector hits triggers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .detectors.base import ClassifierLabel, DetectionAction, Direction

logger = logging.getLogger(__name__)

_VALID_ACTIONS: frozenset[str] = frozenset(("allow", "warn", "block", "rewrite"))

_VALID_WHEN_KEYS: frozenset[str] = frozenset(
    (
        "direction",
        "method",
        "classifier",
        "detector_score_at_least",
        "tool_args_match_any",
        "rules_hit_any",
    )
)


@dataclass(frozen=True)
class PolicyRule:
    name: str
    when: dict[str, Any]
    action: DetectionAction
    message: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    action: DetectionAction
    matched_rule: str | None
    message: str | None = None


class Policy:
    """In-memory policy. Construct via :meth:`from_file` or :meth:`from_dict`."""

    def __init__(
        self,
        rules: list[PolicyRule],
        *,
        default: DetectionAction = "allow",
    ) -> None:
        self._rules = list(rules)
        self._default = default

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)

    @property
    def default(self) -> DetectionAction:
        return self._default

    def __len__(self) -> int:
        return len(self._rules)

    @classmethod
    def from_file(cls, path: Path) -> Policy:
        if not path.is_file():
            raise FileNotFoundError(f"policy file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls._from_dict(data, source_label=str(path))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls._from_dict(data, source_label="<dict>")

    @classmethod
    def _from_dict(cls, data: Any, *, source_label: str) -> Policy:
        if not isinstance(data, dict):
            raise ValueError(f"{source_label}: top level must be a mapping")
        default = data.get("default", "allow")
        if default not in _VALID_ACTIONS:
            raise ValueError(f"{source_label}: invalid default action {default!r}")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError(f"{source_label}: 'rules' must be a list")

        compiled: list[PolicyRule] = []
        seen_names: set[str] = set()
        for raw in raw_rules:
            rule = _compile_rule(raw, source_label)
            if rule.name in seen_names:
                raise ValueError(f"{source_label}: duplicate rule name {rule.name!r}")
            seen_names.add(rule.name)
            compiled.append(rule)
        return cls(compiled, default=default)

    def decide(
        self,
        *,
        direction: Direction,
        method: str | None,
        score: float,
        classifier: ClassifierLabel | None,
        rules_hit: tuple[str, ...],
        raw: str,
    ) -> PolicyDecision:
        for rule in self._rules:
            if _matches(
                rule.when,
                direction=direction,
                method=method,
                score=score,
                classifier=classifier,
                rules_hit=rules_hit,
                raw=raw,
            ):
                return PolicyDecision(
                    action=rule.action,
                    matched_rule=rule.name,
                    message=rule.message,
                )
        return PolicyDecision(action=self._default, matched_rule=None)


def _compile_rule(raw: Any, source_label: str) -> PolicyRule:
    if not isinstance(raw, dict):
        raise ValueError(f"{source_label}: each rule must be a mapping")

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{source_label}: rule missing 'name'")

    when = raw.get("when", {})
    if not isinstance(when, dict):
        raise ValueError(f"{source_label}: rule {name!r} 'when' must be a mapping")

    unknown_keys = set(when) - _VALID_WHEN_KEYS
    if unknown_keys:
        raise ValueError(
            f"{source_label}: rule {name!r} has unknown 'when' keys: "
            f"{sorted(unknown_keys)}. A typo here would silently match every "
            f"frame — see ADR-0004 §6 for the allowed keys."
        )

    action = raw.get("action", "allow")
    if action not in _VALID_ACTIONS:
        raise ValueError(f"{source_label}: rule {name!r} has invalid action {action!r}")

    if action == "block" and not when:
        raise ValueError(
            f"{source_label}: rule {name!r} cannot use 'block' with an empty "
            "'when:' (it would block every frame). If that is truly what you "
            "want, write a policy with default: block instead."
        )

    message = raw.get("message")
    return PolicyRule(
        name=name,
        when=dict(when),
        action=action,
        message=str(message) if message is not None else None,
    )


def default_policy() -> Policy:
    """Sensible defaults when no ``policies.yaml`` is provided.

    Mirrors ``config/policies.yaml`` (ADR-0004 §6): block on high detector
    score, warn on bare classifier signal, block any frame whose rules
    detector fired a shell-injection pattern. INSTRUCTION-only signal
    warns rather than blocks because a 3 B parameter local model is too
    false-positive-prone to use as a blocker by default — switch to
    ``block`` in your own ``policies.yaml`` if you want paranoid mode.
    """
    return Policy.from_dict(
        {
            "default": "allow",
            "rules": [
                {
                    "name": "block_high_score_s2c",
                    "when": {
                        "direction": "server_to_client",
                        "detector_score_at_least": 0.85,
                    },
                    "action": "block",
                    "message": "high-confidence prompt injection detected",
                },
                {
                    "name": "warn_classifier_instruction",
                    "when": {
                        "direction": "server_to_client",
                        "classifier": "INSTRUCTION",
                    },
                    "action": "warn",
                    "message": "classifier flagged instruction-like data",
                },
                {
                    "name": "block_shell_injection_c2s",
                    "when": {
                        "direction": "client_to_server",
                        "rules_hit_any": [
                            "shell.rm_rf_root_or_home",
                            "shell.curl_pipe_to_shell",
                            "shell.base64_decoded_pipe",
                            "shell.reverse_shell_classic",
                        ],
                    },
                    "action": "block",
                    "message": "shell-injection markers in tool arguments",
                },
                {
                    "name": "warn_history_clearing_c2s",
                    "when": {
                        "direction": "client_to_server",
                        "rules_hit_any": ["shell.history_clearing"],
                    },
                    "action": "warn",
                    "message": "history-clearing markers in tool arguments",
                },
            ],
        }
    )


def _matches(
    when: dict[str, Any],
    *,
    direction: Direction,
    method: str | None,
    score: float,
    classifier: ClassifierLabel | None,
    rules_hit: tuple[str, ...],
    raw: str,
) -> bool:
    """All clauses in ``when`` must match (AND semantics)."""
    if "direction" in when and when["direction"] != direction:
        return False
    if "method" in when and when["method"] != method:
        return False
    if "classifier" in when and when["classifier"] != classifier:
        return False
    if "detector_score_at_least" in when:
        try:
            threshold = float(when["detector_score_at_least"])
        except (TypeError, ValueError):
            return False
        if score < threshold:
            return False
    if "tool_args_match_any" in when:
        markers = when["tool_args_match_any"]
        if not isinstance(markers, list):
            return False
        if not any(isinstance(m, str) and m in raw for m in markers):
            return False
    if "rules_hit_any" in when:
        markers = when["rules_hit_any"]
        if not isinstance(markers, list):
            return False
        hit_set = set(rules_hit)
        if not any(isinstance(m, str) and m in hit_set for m in markers):
            return False
    return True
