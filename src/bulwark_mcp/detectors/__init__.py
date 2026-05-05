"""Detection layer (ADR-0004).

Two detectors live here:

- :mod:`.rules` — fast YAML-driven regex matcher.
- :mod:`.llm`   — slow but contextual local LLM classifier (Ollama).

The :mod:`bulwark_mcp.inspector` module composes them.
"""

from .base import (
    ClassifierResult,
    Direction,
    InspectionResult,
    RulesResult,
)

__all__ = [
    "ClassifierResult",
    "Direction",
    "InspectionResult",
    "RulesResult",
]
