"""Local-only statistics aggregation over the audit log (ADR-0005 §1).

The stats layer is read-only: it never mutates the DB and never reaches
the network. It powers ``mcp-firewall stats`` and the (separate)
telemetry payload builder, both of which read the same shape of data
so users can predict exactly what telemetry will report by running
``stats`` first.

Schema is versioned: every JSON output carries ``schema_version: 1``.
We commit to never breaking format-1 fields silently; new fields can
be added in a non-breaking way.
"""

from __future__ import annotations

import collections
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from .storage import Storage

STATS_SCHEMA_VERSION: Final[int] = 1


@dataclass(frozen=True)
class RuleHit:
    id: str
    count: int


@dataclass(frozen=True)
class Stats:
    schema_version: int
    period_start: datetime
    period_end: datetime
    total_events: int
    verdicts: dict[str, int]
    top_rules: list[RuleHit]
    latency_p50_ms: float | None
    latency_p95_ms: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "total_events": self.total_events,
            "verdicts": dict(self.verdicts),
            "top_rules": [{"id": r.id, "count": r.count} for r in self.top_rules],
            "latency_ms": {
                "p50": self.latency_p50_ms,
                "p95": self.latency_p95_ms,
            },
        }


async def compute_stats(storage: Storage, *, since: timedelta) -> Stats:
    """Aggregate events from ``now - since`` to ``now``."""
    end = datetime.now(UTC)
    start = end - since
    conn = storage._required_conn
    start_iso = start.isoformat()
    end_iso = end.isoformat()

    # Total events in the window
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ?",
        (start_iso, end_iso),
    )
    row = await cur.fetchone()
    total = int(row["n"]) if row else 0

    # Verdict counts
    verdicts: dict[str, int] = {"PASS": 0, "WARN": 0, "BLOCK": 0}
    cur = await conn.execute(
        "SELECT det_verdict, COUNT(*) AS n FROM events "
        "WHERE ts >= ? AND ts < ? AND det_verdict IS NOT NULL "
        "GROUP BY det_verdict",
        (start_iso, end_iso),
    )
    for r in await cur.fetchall():
        verdicts[str(r["det_verdict"])] = int(r["n"])

    # Top-5 rules — parse the JSON column in Python so we don't require
    # SQLite's JSON1 extension at runtime.
    rule_counts: collections.Counter[str] = collections.Counter()
    cur = await conn.execute(
        "SELECT det_rules FROM events WHERE ts >= ? AND ts < ? AND det_rules IS NOT NULL",
        (start_iso, end_iso),
    )
    for r in await cur.fetchall():
        try:
            ids = json.loads(r["det_rules"])
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(ids, list):
            rule_counts.update(i for i in ids if isinstance(i, str))
    top_rules = [RuleHit(id=rid, count=cnt) for rid, cnt in rule_counts.most_common(5)]

    # Latency p50 / p95
    cur = await conn.execute(
        "SELECT det_latency_ms FROM events WHERE ts >= ? AND ts < ? AND det_latency_ms IS NOT NULL",
        (start_iso, end_iso),
    )
    samples = [int(r["det_latency_ms"]) for r in await cur.fetchall()]
    p50 = _percentile(samples, 0.50) if samples else None
    p95 = _percentile(samples, 0.95) if samples else None

    return Stats(
        schema_version=STATS_SCHEMA_VERSION,
        period_start=start,
        period_end=end,
        total_events=total,
        verdicts=verdicts,
        top_rules=top_rules,
        latency_p50_ms=p50,
        latency_p95_ms=p95,
    )


def parse_since(value: str) -> timedelta:
    """Parse a window like ``7d``, ``24h``, ``30m`` to a timedelta.

    We deliberately keep this small: three units, no compound forms
    (``2d12h`` etc.). The CLI surface stays predictable.
    """
    if not value:
        raise ValueError("--since must not be empty")
    unit = value[-1].lower()
    try:
        amount = int(value[:-1])
    except ValueError as exc:
        raise ValueError(f"--since must look like '7d', '24h', or '30m'; got {value!r}") from exc
    if amount <= 0:
        raise ValueError("--since must be a positive integer")
    if unit == "d":
        return timedelta(days=amount)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    raise ValueError(f"--since unit must be d, h, or m; got {unit!r}")


def _percentile(samples: list[int], p: float) -> float:
    s = sorted(samples)
    if len(s) == 1:
        return float(s[0])
    rank = (len(s) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(s) - 1)
    frac = rank - lo
    return float(s[lo] + (s[hi] - s[lo]) * frac)
