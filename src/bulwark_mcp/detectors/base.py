"""Shared types for the detection layer.

We deliberately avoid Protocol classes here — every detector has a
narrow public surface and direct dataclass returns are easier to read,
serialise, and freeze. The Inspector composes these by *value*, never
by interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Direction = Literal["client_to_server", "server_to_client"]
ClassifierLabel = Literal["DATA", "INSTRUCTION"]
DetectionVerdict = Literal["PASS", "WARN", "BLOCK"]
DetectionAction = Literal["allow", "warn", "block", "rewrite"]


@dataclass(frozen=True)
class RulesResult:
    """Output of the rules detector.

    Attributes
    ----------
    hits
        Tuple of rule ids that matched the input. Empty when nothing fired.
    score
        Maximum ``score`` across hit rules, in ``[0.0, 1.0]``. Zero when
        no rule fired.
    """

    hits: tuple[str, ...] = ()
    score: float = 0.0

    @property
    def is_hit(self) -> bool:
        return bool(self.hits)


@dataclass(frozen=True)
class ClassifierResult:
    """Output of the LLM classifier.

    ``label`` is ``None`` whenever we did *not* obtain a real verdict —
    the cascade short-circuited, the circuit breaker is open, the input
    was filtered out, or the request timed out. ``reason`` carries a
    machine-readable note ("circuit_open", "cache_hit", "skipped",
    "timeout", "ok") so the audit log keeps full provenance.
    """

    label: ClassifierLabel | None = None
    score: float = 0.0
    reason: str | None = None


@dataclass(frozen=True)
class InspectionResult:
    """End-to-end output of :class:`bulwark_mcp.inspector.Inspector`.

    The pump uses ``action`` to choose between forwarding the original
    bytes and substituting ``replacement``. Everything else is for the
    audit log row.
    """

    verdict: DetectionVerdict
    action: DetectionAction
    score: float
    rules_hit: tuple[str, ...]
    classifier: ClassifierLabel | None
    latency_ms: int
    note: str | None = None
    replacement: str | None = None
    matched_policy: str | None = field(default=None)
