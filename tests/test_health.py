"""Tests for the loopback health endpoint (Week 3, ADR-0005 §2)."""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from pathlib import Path

import httpx

from mcp_firewall.health import HealthState, serve
from mcp_firewall.storage import Storage


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ---------------------------------------------------------------------
# HealthState snapshot
# ---------------------------------------------------------------------


class TestSnapshot:
    async def test_snapshot_on_empty_db(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            state = HealthState(started_at=datetime.now(UTC), storage=storage)
            snap = await state.snapshot()
        assert snap["status"] == "ok"
        assert snap["events_processed"] == 0
        assert snap["last_event_ts"] is None
        assert "version" in snap
        assert snap["uptime_s"] >= 0.0

    async def test_snapshot_reflects_audit_log_count(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            sid = await storage.start_session(server_command="cat")
            from mcp_firewall.models import EventRecord

            await storage.insert_events(
                [
                    EventRecord(
                        session_id=sid,
                        direction="server_to_client",
                        kind="response",
                        raw="{}",
                    )
                    for _ in range(3)
                ]
            )
            state = HealthState(started_at=datetime.now(UTC), storage=storage)
            snap = await state.snapshot()
        assert snap["events_processed"] == 3
        assert snap["last_event_ts"] is not None


# ---------------------------------------------------------------------
# HTTP behaviour (real server on a free port)
# ---------------------------------------------------------------------


class TestHttpServer:
    async def test_get_health_returns_200_json(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            state = HealthState(started_at=datetime.now(UTC), storage=storage)
            port = _free_port()
            server = await serve(state, port=port)
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.get(f"http://127.0.0.1:{port}/health")
            finally:
                server.close()
                await server.wait_closed()
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/json"
        body = r.json()
        assert body["status"] == "ok"
        assert "version" in body
        assert body["events_processed"] == 0

    async def test_unknown_path_returns_404(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            state = HealthState(started_at=datetime.now(UTC), storage=storage)
            port = _free_port()
            server = await serve(state, port=port)
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.get(f"http://127.0.0.1:{port}/nope")
            finally:
                server.close()
                await server.wait_closed()
        assert r.status_code == 404
        assert r.json()["status"] == "not found"

    async def test_post_returns_405(self, tmp_path: Path) -> None:
        async with Storage(tmp_path / "log.db") as storage:
            state = HealthState(started_at=datetime.now(UTC), storage=storage)
            port = _free_port()
            server = await serve(state, port=port)
            try:
                async with httpx.AsyncClient() as client:
                    r = await client.post(f"http://127.0.0.1:{port}/health")
            finally:
                server.close()
                await server.wait_closed()
        assert r.status_code == 405

    async def test_listener_is_loopback_only(self, tmp_path: Path) -> None:
        # The listener must bind to 127.0.0.1 only — never a wildcard.
        async with Storage(tmp_path / "log.db") as storage:
            state = HealthState(started_at=datetime.now(UTC), storage=storage)
            port = _free_port()
            server = await serve(state, port=port)
            try:
                # asyncio.Server exposes its bound sockets via ``sockets``;
                # the attribute is missing from the abstract type but always
                # present on the concrete asyncio.Server instance.
                sockets = list(getattr(server, "sockets", None) or [])
                assert sockets, "server has no bound sockets"
                hosts = {s.getsockname()[0] for s in sockets}
                assert hosts == {"127.0.0.1"}, (
                    f"health endpoint must be loopback-only; bound to {hosts}"
                )
            finally:
                server.close()
                await server.wait_closed()

    async def test_handler_survives_connection_reset(self, tmp_path: Path) -> None:
        # A peer that disconnects mid-write must not crash the listener.
        async with Storage(tmp_path / "log.db") as storage:
            state = HealthState(started_at=datetime.now(UTC), storage=storage)
            port = _free_port()
            server = await serve(state, port=port)
            try:
                # Open a raw TCP socket, send junk, close immediately.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(("127.0.0.1", port))
                    s.sendall(b"not even an HTTP request")
                    s.close()
                # A subsequent valid request must still succeed.
                async with httpx.AsyncClient() as client:
                    r = await client.get(f"http://127.0.0.1:{port}/health")
                assert r.status_code == 200
            finally:
                server.close()
                await server.wait_closed()
