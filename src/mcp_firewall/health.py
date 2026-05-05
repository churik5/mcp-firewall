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


@dataclass
class HealthState:
    """Mutable state surfaced by ``GET /health``.

    ``started_at`` is captured by ``run_proxy`` at startup. Counters
    are queried on demand from the live :class:`Storage` so the
    endpoint's body always reflects the durable audit log, not an
    in-memory mirror that could drift after a write failure.
    """

    started_at: datetime
    storage: Storage

    async def snapshot(self) -> dict[str, Any]:
        events_processed = await self.storage.event_count()
        last_event_ts = await self._last_event_ts()
        return {
            "status": "ok",
            "version": __version__,
            "uptime_s": (datetime.now(UTC) - self.started_at).total_seconds(),
            "events_processed": events_processed,
            "last_event_ts": last_event_ts.isoformat() if last_event_ts else None,
        }

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
            await _serve_one(state, reader, writer)
        except Exception as exc:
            logger.warning("health: handler raised %r", exc)
            with suppress(Exception):
                await _respond(writer, 500, {"status": "error"})
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    return await asyncio.start_server(_handle, host="127.0.0.1", port=port)


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
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
}
