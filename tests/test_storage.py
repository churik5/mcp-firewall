"""Tests for the SQLite storage layer."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from bulwark_mcp.models import EventRecord
from bulwark_mcp.storage import EventBuffer, Storage


def _event(session_id: int, **kw: object) -> EventRecord:
    defaults: dict[str, object] = {
        "direction": "client_to_server",
        "kind": "request",
        "raw": "{}",
        "method": "ping",
        "msg_id": "1",
    }
    defaults.update(kw)
    return EventRecord(session_id=session_id, **defaults)  # type: ignore[arg-type]


class TestStorage:
    async def test_creates_schema_on_open(self, storage: Storage) -> None:
        # Idempotent — reopening must not raise
        await storage.close()
        await storage.open()
        await storage.close()
        await storage.open()
        assert await storage.event_count() == 0

    async def test_session_lifecycle(self, storage: Storage) -> None:
        sid = await storage.start_session(server_command="cat", client_pid=42)
        assert sid >= 1
        await storage.set_server_pid(sid, 4242)
        await storage.end_session(sid, exit_code=0)

    async def test_round_trip_event(self, storage: Storage) -> None:
        sid = await storage.start_session(server_command="cat")
        ev = _event(sid)
        await storage.insert_events([ev])
        rows = await storage.latest_events(limit=10)
        assert len(rows) == 1
        assert rows[0]["method"] == "ping"
        assert rows[0]["direction"] == "client_to_server"
        assert rows[0]["msg_id"] == "1"

    async def test_latest_events_returns_chronological_order(self, storage: Storage) -> None:
        sid = await storage.start_session(server_command="cat")
        await storage.insert_events([_event(sid, method=f"m{i}") for i in range(5)])
        rows = await storage.latest_events(limit=10)
        assert [r["method"] for r in rows] == ["m0", "m1", "m2", "m3", "m4"]

    async def test_latest_events_respects_since_id(self, storage: Storage) -> None:
        sid = await storage.start_session(server_command="cat")
        await storage.insert_events([_event(sid, method=f"m{i}") for i in range(5)])
        rows = await storage.latest_events(limit=10)
        cutoff = int(rows[2]["id"])
        await storage.insert_events([_event(sid, method="new")])
        new_rows = await storage.latest_events(limit=10, since_id=cutoff)
        # new_rows must include m3, m4, and "new" — i.e. only ids strictly above cutoff
        methods = [r["method"] for r in new_rows]
        assert "new" in methods
        assert all(int(r["id"]) > cutoff for r in new_rows)

    async def test_check_constraint_rejects_bad_direction(self, storage: Storage) -> None:
        sid = await storage.start_session(server_command="cat")
        # Crafted with a manual SQL bypass — pydantic stops it earlier in
        # production, but the DB constraint is the second line of defence.
        conn = storage._required_conn
        with pytest.raises(Exception):  # noqa: B017
            await conn.execute(
                "INSERT INTO events (session_id, ts, direction, kind, raw) VALUES (?, ?, ?, ?, ?)",
                (sid, "2026-05-04T00:00:00Z", "sideways", "raw", "{}"),
            )
            await conn.commit()


class TestEventBuffer:
    async def test_drains_in_background(self, storage: Storage, tmp_path: Path) -> None:
        sid = await storage.start_session(server_command="cat")
        events = [_event(sid, method=f"m{i}") for i in range(20)]
        async with EventBuffer(
            storage,
            queue_max=1000,
            batch_size=5,
            batch_interval_s=0.01,
        ) as buf:
            for e in events:
                buf.record(e)
            # Give the writer task one batch interval to drain the queue
            for _ in range(20):
                if await storage.event_count() == 20:
                    break
                await asyncio.sleep(0.05)
        assert await storage.event_count() == 20
        assert buf.dropped == 0

    async def test_drops_when_queue_full(self, storage: Storage) -> None:
        sid = await storage.start_session(server_command="cat")
        # Tiny queue + slow drain (large interval) so the buffer fills before
        # the writer can flush.
        async with EventBuffer(
            storage,
            queue_max=2,
            batch_size=1,
            batch_interval_s=10.0,
        ) as buf:
            for i in range(10):
                buf.record(_event(sid, method=f"m{i}"))
        # On exit __aexit__ drains what it can, but the dropped counter
        # records the overflow that happened on the hot path.
        assert buf.dropped > 0
