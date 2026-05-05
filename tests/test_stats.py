"""Tests for the stats aggregator (Week 3, ADR-0005 §1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bulwark_mcp.models import EventRecord
from bulwark_mcp.stats import (
    STATS_SCHEMA_VERSION,
    compute_stats,
    parse_since,
)
from bulwark_mcp.storage import Storage

# ---------------------------------------------------------------------
# parse_since
# ---------------------------------------------------------------------


class TestParseSince:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("7d", timedelta(days=7)),
            ("1d", timedelta(days=1)),
            ("24h", timedelta(hours=24)),
            ("1h", timedelta(hours=1)),
            ("30m", timedelta(minutes=30)),
            ("5m", timedelta(minutes=5)),
        ],
    )
    def test_valid_inputs(self, value: str, expected: timedelta) -> None:
        assert parse_since(value) == expected

    @pytest.mark.parametrize(
        "value",
        ["", "abc", "0d", "-5h", "5x", "h", "5", "1.5d"],
    )
    def test_invalid_inputs_raise(self, value: str) -> None:
        with pytest.raises(ValueError):
            parse_since(value)


# ---------------------------------------------------------------------
# compute_stats helpers
# ---------------------------------------------------------------------


def _event(
    sid: int,
    *,
    ts: datetime,
    verdict: str | None = None,
    rules: list[str] | None = None,
    latency_ms: int | None = None,
    direction: str = "server_to_client",
    kind: str = "response",
    raw: str = "{}",
) -> EventRecord:
    return EventRecord(
        session_id=sid,
        ts=ts,
        direction=direction,  # type: ignore[arg-type]
        kind=kind,  # type: ignore[arg-type]
        raw=raw,
        det_verdict=verdict,  # type: ignore[arg-type]
        det_rules=rules,
        det_latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------
# compute_stats
# ---------------------------------------------------------------------


class TestComputeStats:
    async def test_empty_db_returns_zero_counts(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            stats = await compute_stats(storage, since=timedelta(days=7))
        assert stats.schema_version == STATS_SCHEMA_VERSION
        assert stats.total_events == 0
        assert stats.verdicts == {"PASS": 0, "WARN": 0, "BLOCK": 0}
        assert stats.top_rules == []
        assert stats.latency_p50_ms is None
        assert stats.latency_p95_ms is None

    async def test_counts_verdicts_in_window(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            now = datetime.now(UTC)
            await storage.insert_events(
                [
                    _event(sid, ts=now - timedelta(hours=1), verdict="PASS"),
                    _event(sid, ts=now - timedelta(hours=2), verdict="PASS"),
                    _event(sid, ts=now - timedelta(hours=3), verdict="BLOCK"),
                    _event(sid, ts=now - timedelta(hours=4), verdict="WARN"),
                ]
            )
            stats = await compute_stats(storage, since=timedelta(days=1))
        assert stats.total_events == 4
        assert stats.verdicts == {"PASS": 2, "WARN": 1, "BLOCK": 1}

    async def test_excludes_events_outside_window(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            now = datetime.now(UTC)
            await storage.insert_events(
                [
                    _event(sid, ts=now - timedelta(hours=1), verdict="PASS"),
                    _event(sid, ts=now - timedelta(days=8), verdict="BLOCK"),
                ]
            )
            stats = await compute_stats(storage, since=timedelta(days=7))
        assert stats.total_events == 1
        assert stats.verdicts["PASS"] == 1
        assert stats.verdicts["BLOCK"] == 0

    async def test_top_rules_ordered_and_limited_to_5(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            now = datetime.now(UTC)
            # Build a known rule-hit distribution.
            counts = {
                "rule.a": 8,
                "rule.b": 5,
                "rule.c": 3,
                "rule.d": 2,
                "rule.e": 1,
                "rule.f": 1,  # ties for last; should be dropped from top-5
            }
            events: list[EventRecord] = []
            for rule_id, n in counts.items():
                for _ in range(n):
                    events.append(
                        _event(
                            sid,
                            ts=now - timedelta(minutes=1),
                            rules=[rule_id],
                        )
                    )
            await storage.insert_events(events)
            stats = await compute_stats(storage, since=timedelta(hours=1))
        assert len(stats.top_rules) == 5
        assert [h.id for h in stats.top_rules] == [
            "rule.a",
            "rule.b",
            "rule.c",
            "rule.d",
            "rule.e",
        ]
        assert stats.top_rules[0].count == 8

    async def test_latency_percentiles(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            now = datetime.now(UTC)
            # 100 latencies from 1..100 — clean p50=50.5, p95=95.05.
            events = [
                _event(
                    sid,
                    ts=now - timedelta(minutes=1),
                    latency_ms=ms,
                )
                for ms in range(1, 101)
            ]
            await storage.insert_events(events)
            stats = await compute_stats(storage, since=timedelta(hours=1))
        assert stats.latency_p50_ms is not None
        assert stats.latency_p95_ms is not None
        # Linear interpolation: rank=99*0.50=49.5 → between samples[49]=50 and samples[50]=51 → 50.5
        assert stats.latency_p50_ms == pytest.approx(50.5)
        # rank=99*0.95=94.05 → between samples[94]=95 and samples[95]=96 → 95.05
        assert stats.latency_p95_ms == pytest.approx(95.05)

    async def test_to_dict_is_versioned_and_iso_timestamps(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            stats = await compute_stats(storage, since=timedelta(days=1))
        d = stats.to_dict()
        assert d["schema_version"] == 1
        # ISO 8601 with timezone offset
        assert "T" in d["period_start"] and "+" in d["period_start"]
        assert "T" in d["period_end"] and "+" in d["period_end"]
        assert d["verdicts"] == {"PASS": 0, "WARN": 0, "BLOCK": 0}
        assert d["top_rules"] == []
        assert d["latency_ms"] == {"p50": None, "p95": None}

    async def test_malformed_det_rules_json_is_ignored(self, tmp_path: Path) -> None:
        # If a row has corrupt det_rules JSON we must not crash; just skip it.
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            conn = storage._required_conn
            now_iso = datetime.now(UTC).isoformat()
            await conn.execute(
                "INSERT INTO events (session_id, ts, direction, kind, raw, det_rules) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (sid, now_iso, "server_to_client", "response", "{}", "not-json"),
            )
            await conn.commit()
            stats = await compute_stats(storage, since=timedelta(hours=1))
        # No crash, no rule hits.
        assert stats.top_rules == []
