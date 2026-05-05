"""Inspector — orchestrates the rules + LLM cascade and applies policy.

The :class:`Inspector` is the only object the proxy pump talks to. It
swallows every detector failure and never raises out — at worst it
returns ``InspectionResult(verdict="WARN", note="inspection_error")``,
which preserves Week 1 behaviour ("forward the original").

ADR-0004 §2 — cascade:

1. ``RulesEngine.detect`` always runs (cheap, deterministic).
2. If ``rules.score >= short_circuit_threshold`` → take the rules verdict.
3. Otherwise, on **server_to_client** frames whose body looks like a
   tool result, ask the LLM classifier with a remaining-budget timeout.
4. Combine ``score = max(rules, classifier)``.
5. Hand off to :class:`Policy` for the final action.
6. If action is ``block``, compose a sanitised replacement line.
7. If total inspector latency exceeds ``max_latency_ms * 1.25``, fall
   back to ``WARN`` with note ``inspection_timeout``.

Block replacement (ADR-0004 §5):

- s2c response → ``result.content`` becomes a single text block with
  ``isError: true`` and a ``trace=<hex>`` correlation id we also record
  on the audit row.
- c2s request → we synthesise a JSON-RPC error reply. The proxy pump
  is responsible for routing that reply back to the *client* and never
  forwarding the original to the server.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any

from .detectors.base import (
    ClassifierLabel,
    DetectionAction,
    DetectionVerdict,
    Direction,
    InspectionResult,
)
from .detectors.llm import OllamaClassifier
from .detectors.rules import RulesEngine
from .models import MCPRequest, MCPResponse, ParsedMessage
from .policy import Policy

logger = logging.getLogger(__name__)


class Inspector:
    """Orchestrator for the detection cascade.

    Construction does no I/O. Each :meth:`inspect` call is bounded by
    ``max_latency_ms``; the underlying LLM is invoked through
    :func:`asyncio.wait_for` with the remaining budget so a slow Ollama
    cannot stall the pump beyond the user-configured ceiling.
    """

    def __init__(
        self,
        *,
        rules: RulesEngine,
        classifier: OllamaClassifier | None,
        policy: Policy,
        max_latency_ms: int = 200,
        short_circuit_threshold: float = 0.9,
        min_classify_chars: int = 50,
        max_classify_chars: int = 100_000,
        hard_abort_factor: float = 1.25,
    ) -> None:
        self._rules = rules
        self._classifier = classifier
        self._policy = policy
        self._max_latency_ms = max_latency_ms
        self._short_circuit_threshold = short_circuit_threshold
        self._min_classify_chars = min_classify_chars
        self._max_classify_chars = max_classify_chars
        self._hard_abort_ms = int(max_latency_ms * hard_abort_factor)

    async def inspect(
        self,
        *,
        raw: str,
        parsed: ParsedMessage | None,
        direction: Direction,
        method_hint: str | None = None,
    ) -> InspectionResult:
        start = time.perf_counter()

        rules_result = self._rules.detect(raw, direction=direction)
        score = rules_result.score
        classifier_label: ClassifierLabel | None = None
        classifier_note: str = self._initial_classifier_note(direction, score)

        if classifier_note == "candidate" and self._classifier is not None:
            classifier_text, shape_note = _extract_classifiable_text(parsed)
            if shape_note != "candidate":
                classifier_note = shape_note
            else:
                classifier_note = self._size_gate(classifier_text)
            if classifier_note == "candidate" and classifier_text is not None:
                budget_remaining_s = max(
                    0.001,
                    (self._max_latency_ms / 1000.0) - (time.perf_counter() - start),
                )
                try:
                    cls_result = await asyncio.wait_for(
                        self._classifier.classify(classifier_text),
                        timeout=budget_remaining_s,
                    )
                    classifier_label = cls_result.label
                    classifier_note = cls_result.reason or "ok"
                    if cls_result.score > score:
                        score = cls_result.score
                except TimeoutError:
                    classifier_note = "inspection_timeout"
                except Exception as exc:
                    logger.warning("inspector: classifier raised %r", exc)
                    classifier_note = f"classifier_error:{type(exc).__name__}"

        latency_ms = int((time.perf_counter() - start) * 1000)

        if latency_ms > self._hard_abort_ms:
            # The whole inspect() spent too long; downgrade to a soft warn so
            # the proxy still forwards the original frame.
            return InspectionResult(
                verdict="WARN",
                action="warn",
                score=score,
                rules_hit=rules_result.hits,
                classifier=classifier_label,
                latency_ms=latency_ms,
                note="inspection_timeout",
            )

        decision = self._policy.decide(
            direction=direction,
            method=method_hint,
            score=score,
            classifier=classifier_label,
            rules_hit=rules_result.hits,
            raw=raw,
        )

        verdict = _verdict_for(decision.action)
        replacement: str | None = None
        note = classifier_note if classifier_note != "ok" else None

        if decision.action == "block":
            trace_id = _trace_id(raw)
            replacement = _compose_block_replacement(
                parsed=parsed,
                direction=direction,
                message=decision.message or "prompt injection detected",
                trace_id=trace_id,
            )
            if replacement is None:
                # We cannot safely substitute (e.g. parse_error frame on
                # s2c). Downgrade to warn and let the original through.
                logger.info(
                    "inspector: cannot compose block replacement; downgrading to warn (rule=%s)",
                    decision.matched_rule,
                )
                return InspectionResult(
                    verdict="WARN",
                    action="warn",
                    score=score,
                    rules_hit=rules_result.hits,
                    classifier=classifier_label,
                    latency_ms=latency_ms,
                    note="downgraded:no_replacement",
                    matched_policy=decision.matched_rule,
                )
            note = note or f"trace={trace_id}"

        return InspectionResult(
            verdict=verdict,
            action=decision.action,
            score=score,
            rules_hit=rules_result.hits,
            classifier=classifier_label,
            latency_ms=latency_ms,
            note=note,
            replacement=replacement,
            matched_policy=decision.matched_rule,
        )

    def _initial_classifier_note(self, direction: Direction, score: float) -> str:
        if self._classifier is None:
            return "skipped:disabled"
        if direction != "server_to_client":
            return "skipped:c2s"
        if score >= self._short_circuit_threshold:
            return "skipped:rules_short_circuit"
        return "candidate"

    def _size_gate(self, text: str | None) -> str:
        if text is None:
            return "skipped:not_candidate"
        n = len(text)
        if n < self._min_classify_chars:
            return "skipped:too_short"
        if n > self._max_classify_chars:
            return "skipped:too_long"
        return "candidate"


def _extract_classifiable_text(parsed: ParsedMessage | None) -> tuple[str | None, str]:
    """Return ``(text, shape_note)``.

    Possible ``shape_note`` values:

    - ``"candidate"``         — caller should run the size gate on the text.
    - ``"skipped:not_candidate"`` — frame is not a tool-result-shaped response.
    - ``"skipped:non_text_content"`` — frame *is* a tool-result candidate
      (has ``result.content`` array) but contains only non-text blocks
      (images, resources, vendor extensions). Week-3 audit fix: the LLM
      cannot inspect bytes; we surface the skip reason in the audit log.
    """
    if not isinstance(parsed, MCPResponse) or parsed.result is None:
        return None, "skipped:not_candidate"
    result = parsed.result
    if not isinstance(result, dict):
        return None, "skipped:not_candidate"
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return None, "skipped:not_candidate"

    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)

    if not parts:
        # Result has content blocks but none are text — image, resource,
        # or vendor extension. Detector has nothing to chew on; we
        # forward the original and surface the reason in audit.
        return None, "skipped:non_text_content"

    return "\n".join(parts), "candidate"


def _verdict_for(action: DetectionAction) -> DetectionVerdict:
    if action == "block":
        return "BLOCK"
    if action == "warn":
        return "WARN"
    return "PASS"


def _trace_id(raw: str) -> str:
    """8-hex-digit correlation id; unguessable.

    ``raw`` is intentionally not part of the seed — ``os.urandom(8)``
    already gives unguessability and hashing the entire (potentially
    multi-megabyte) frame on every block was a hot-path waste. The
    parameter is kept for forward-compat in case we want to bind the
    trace to the frame's content hash later.
    """
    del raw  # intentionally unused; see docstring
    seed = f"{time.perf_counter_ns()}".encode() + os.urandom(8)
    return hashlib.sha1(seed).hexdigest()[:8]  # noqa: S324 — non-crypto trace id


def _compose_block_replacement(
    *,
    parsed: ParsedMessage | None,
    direction: Direction,
    message: str,
    trace_id: str,
) -> str | None:
    """Build the JSON-RPC line we forward instead of the original.

    Returns ``None`` when we lack the structure to build a safe
    replacement (parse_error frames, notifications, etc.). The
    inspector then downgrades the action to ``warn``.
    """
    if direction == "server_to_client":
        if not isinstance(parsed, MCPResponse):
            return None
        body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": parsed.id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"[bulwark-mcp blocked: {message}. trace={trace_id}]",
                    }
                ],
                "isError": True,
            },
        }
        return json.dumps(body, separators=(",", ":"))

    # client_to_server — synthesise an error reply that the pump will
    # send back to the *client* (never forwarded to the real server).
    if isinstance(parsed, MCPRequest):
        body = {
            "jsonrpc": "2.0",
            "id": parsed.id,
            "error": {
                "code": -32099,
                "message": f"blocked by bulwark-mcp: {message}",
                "data": {"trace": trace_id},
            },
        }
        return json.dumps(body, separators=(",", ":"))

    return None
