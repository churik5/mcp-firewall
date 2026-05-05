"""Loopback HTTP health endpoint (ADR-0005 §2).

Tiny ``asyncio.start_server`` listener bound to ``127.0.0.1:<port>``.
Handles exactly one request shape: ``GET /health`` → 200 JSON. Anything
else gets a 404 or 405. There is no authentication and no TLS — the
listener is loopback-only on purpose. If you want it exposed, put it
behind a reverse proxy you trust.

The implementation is deliberately minimal so we don't pull in
``aiohttp`` or any other HTTP server dep. We parse the request line and
a small header block by hand and write a fixed-shape response.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .storage import Storage

logger = logging.getLogger(__name__)

_MAX_REQUEST_LINE = 8 * 1024
_MAX_HEADER_BYTES = 16 * 1024
_REQUEST_TIMEOUT_S = 5.0
_SNAPSHOT_TTL_S = 1.0


@dataclass
class HealthState:
    """Mutable state surfaced by ``GET /health``.

    ``started_at`` is captured by ``run_proxy`` at startup. Counters
    come from the live :class:`Storage` but are cached for 1 s
    (``_SNAPSHOT_TTL_S``) — Week-4 audit fix to prevent a hostile
    localhost peer from starving the writer by hammering ``/health``
    and forcing a full table scan on every probe.
    """

    started_at: datetime
    storage: Storage
    _cache: dict[str, Any] | None = None
    _cache_ts: float = 0.0
    _lock: asyncio.Lock | None = None

    async def snapshot(self) -> dict[str, Any]:
        if self._lock is None:
            # Lazy init so the dataclass remains constructible without an
            # event loop — useful in tests.
            self._lock = asyncio.Lock()
        async with self._lock:
            now = asyncio.get_running_loop().time()
            if self._cache is not None and now - self._cache_ts < _SNAPSHOT_TTL_S:
                # Refresh only the uptime (cheap); other fields are cached.
                cached = dict(self._cache)
                cached["uptime_s"] = (datetime.now(UTC) - self.started_at).total_seconds()
                return cached
            events_processed = await self.storage.event_count()
            last_event_ts = await self._last_event_ts()
            snap: dict[str, Any] = {
                "status": "ok",
                "version": __version__,
                "uptime_s": (datetime.now(UTC) - self.started_at).total_seconds(),
                "events_processed": events_processed,
                "last_event_ts": last_event_ts.isoformat() if last_event_ts else None,
            }
            self._cache = dict(snap)
            self._cache_ts = now
            return snap

    async def _last_event_ts(self) -> datetime | None:
        rows = await self.storage.latest_events(limit=1)
        if not rows:
            return None
        return datetime.fromisoformat(rows[-1]["ts"])


async def serve(state: HealthState, *, port: int) -> asyncio.AbstractServer:
    """Start the listener and return the asyncio server handle.

    Caller is responsible for ``server.close()`` + ``await
    server.wait_closed()`` on shutdown. Bind failures (port in use,
    permissions) propagate — the caller in ``run_proxy`` catches them
    and logs a warning so a misconfigured ``--health-port`` cannot
    crash the proxy.
    """

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # Week-4 audit fix: per-connection wall-clock timeout closes
            # the slowloris path — a peer that holds the socket open
            # without sending a full request can no longer wedge an
            # event-loop slot indefinitely.
            await asyncio.wait_for(
                _serve_one(state, reader, writer),
                timeout=_REQUEST_TIMEOUT_S,
            )
        except TimeoutError:
            with suppress(Exception):
                await _respond(writer, 408, {"status": "request timeout"})
        except Exception as exc:
            logger.warning("health: handler raised %r", exc)
            with suppress(Exception):
                await _respond(writer, 500, {"status": "error"})
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    return await asyncio.start_server(
        _handle,
        host="127.0.0.1",
        port=port,
        # Bound the StreamReader buffer so a peer cannot ship megabytes
        # on the request line before we reject it.
        limit=_MAX_REQUEST_LINE,
    )


async def _serve_one(
    state: HealthState,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    request_line = await reader.readline()
    if not request_line or len(request_line) > _MAX_REQUEST_LINE:
        await _respond(writer, 400, {"status": "bad request"})
        return

    parts = request_line.decode("ascii", errors="replace").split()
    if len(parts) < 2:
        await _respond(writer, 400, {"status": "bad request"})
        return
    method, path = parts[0].upper(), parts[1]

    # Drain headers — bounded so a hostile client can't grow our buffer.
    consumed = len(request_line)
    while True:
        if consumed > _MAX_HEADER_BYTES:
            await _respond(writer, 431, {"status": "headers too large"})
            return
        line = await reader.readline()
        consumed += len(line)
        if line in (b"\r\n", b"\n", b""):
            break

    if method != "GET":
        await _respond(writer, 405, {"status": "method not allowed"})
        return
    if path != "/health":
        await _respond(writer, 404, {"status": "not found"})
        return

    body = await state.snapshot()
    await _respond(writer, 200, body)


async def _respond(writer: asyncio.StreamWriter, status: int, body: dict[str, Any]) -> None:
    body_bytes = json.dumps(body).encode("utf-8")
    headers = (
        f"HTTP/1.1 {status} {_REASON.get(status, 'OK')}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    writer.write(headers + body_bytes)
    with suppress(ConnectionResetError, BrokenPipeError):
        await writer.drain()


_REASON: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
}
