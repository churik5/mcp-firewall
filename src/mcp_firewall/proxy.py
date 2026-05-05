"""stdio proxy between an MCP client (e.g. Claude Desktop) and an MCP server.

See ADR-0001. The shape is intentionally small:

- We launch the real server as a subprocess with no shell (argv form).
- Two pumps copy newline-delimited frames between the client and the server.
- Every frame is parsed best-effort and pushed onto an :class:`EventBuffer`
  for asynchronous, batched persistence.
- We never write our own diagnostics to stdout — that channel belongs to
  the JSON-RPC frames flowing to the client.

I/O abstraction
---------------

In production the proxy is launched by Claude Desktop, so stdin/stdout are
anonymous pipes — :func:`asyncio.AbstractEventLoop.connect_read_pipe` and
``connect_write_pipe`` accept those happily. When the proxy is launched from
a normal shell or under test runners, those fds may be a tty or a regular
file, which the asyncio pipe transports refuse with ``ValueError``. We fall
back to blocking I/O on a worker thread, exposed through the same async
:class:`_LineReader` / :class:`_LineWriter` interface so the pump code stays
unchanged.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass
from typing import IO, Literal, Protocol, cast

from .config import Settings
from .detectors.base import InspectionResult
from .detectors.llm import OllamaClassifier
from .detectors.rules import RulesEngine
from .inspector import Inspector
from .models import EventRecord, parse_frame, split_batch
from .policy import Policy, default_policy
from .storage import EventBuffer, Storage

Direction = Literal["client_to_server", "server_to_client"]

logger = logging.getLogger(__name__)

DEFAULT_LINE_LIMIT_BYTES = 8 * 1024 * 1024  # 8 MiB — generous for tool results


@dataclass(frozen=True)
class ProxyResult:
    exit_code: int
    events_dropped: int


class _LineReader(Protocol):
    async def readline(self) -> bytes: ...
    def close(self) -> None: ...


class _LineWriter(Protocol):
    async def write_line(self, data: bytes) -> bool:
        """Write ``data`` and flush. Returns ``False`` once the peer is gone."""
        ...

    def close(self) -> None: ...
    async def aclose(self) -> None:
        """Close and wait for the underlying transport to actually shut.

        Implementations that wrap :class:`asyncio.StreamWriter` need this so
        the peer sees EOF promptly; for blocking writers it is a no-op.
        """
        ...

    def is_closing(self) -> bool: ...


async def run_proxy(
    server_command: str,
    *,
    settings: Settings,
    line_limit: int = DEFAULT_LINE_LIMIT_BYTES,
) -> ProxyResult:
    """Run the proxy until either side closes. Returns the child's exit code."""
    argv = shlex.split(server_command)
    if not argv:
        raise ValueError("--server must contain an executable")

    storage = Storage(settings.db_path)
    await storage.open()
    try:
        session_id = await storage.start_session(
            server_command=server_command,
            client_pid=os.getppid(),
        )

        child = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr.fileno(),
        )
        if child.stdin is None or child.stdout is None:
            raise RuntimeError("subprocess pipes were not created — check argv")

        await _patch_session_with_server_pid(storage, session_id, child.pid)

        client_reader = await _open_client_reader(line_limit)
        client_writer = await _open_client_writer()
        server_reader = _AsyncStreamReader(child.stdout)
        server_writer = _AsyncStreamWriter(child.stdin)

        async with EventBuffer(
            storage,
            queue_max=settings.queue_max,
            batch_size=settings.batch_size,
            batch_interval_s=settings.batch_interval_s,
        ) as buffer:
            stop_event = asyncio.Event()
            _install_signal_handlers(stop_event)

            # ADR-0004 §1: build the inspector if detector is enabled.
            inspector, classifier = await _build_inspector(settings, storage)
            client_write_lock = asyncio.Lock()

            try:
                client_to_server = asyncio.create_task(
                    _pump(
                        src=client_reader,
                        dst=server_writer,
                        reverse_dst=client_writer,
                        direction="client_to_server",
                        inspector=inspector,
                        client_write_lock=client_write_lock,
                        is_client_target=False,
                        buffer=buffer,
                        session_id=session_id,
                        stop_event=stop_event,
                    ),
                    name="pump-c2s",
                )
                server_to_client = asyncio.create_task(
                    _pump(
                        src=server_reader,
                        dst=client_writer,
                        reverse_dst=server_writer,
                        direction="server_to_client",
                        inspector=inspector,
                        client_write_lock=client_write_lock,
                        is_client_target=True,
                        buffer=buffer,
                        session_id=session_id,
                        stop_event=stop_event,
                    ),
                    name="pump-s2c",
                )
                stop_waiter = asyncio.create_task(stop_event.wait(), name="stop-waiter")

                done, _ = await asyncio.wait(
                    {client_to_server, server_to_client, stop_waiter},
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in done:
                    if task is stop_waiter:
                        continue
                    exc = task.exception()
                    if exc is not None and not isinstance(exc, asyncio.CancelledError):
                        logger.error("pump task %s failed: %r", task.get_name(), exc)

                if stop_waiter in done:
                    # Forced shutdown — kill both directions immediately.
                    for task in (client_to_server, server_to_client):
                        task.cancel()
                elif client_to_server in done and server_to_client not in done:
                    # Client EOF. Half-close server stdin (await wait_closed so the
                    # peer actually sees EOF) and let the server drain any pending
                    # replies before we tear down s2c.
                    await server_writer.aclose()
                    try:
                        await asyncio.wait_for(server_to_client, timeout=10.0)
                    except TimeoutError:
                        logger.warning("server did not flush within 10s; cancelling")
                        server_to_client.cancel()
                elif server_to_client in done and client_to_server not in done:
                    # Server EOF / crash. Stop reading from client.
                    client_to_server.cancel()

                # stop_waiter may still be pending — always cancel before awaiting
                # so we never block the shutdown path on an idle event.
                stop_waiter.cancel()
                for task in (client_to_server, server_to_client, stop_waiter):
                    with suppress(asyncio.CancelledError, Exception):
                        await task

                with suppress(ProcessLookupError):
                    if child.returncode is None:
                        await server_writer.aclose()
                        try:
                            await asyncio.wait_for(child.wait(), timeout=2.0)
                        except TimeoutError:
                            child.terminate()
                            try:
                                await asyncio.wait_for(child.wait(), timeout=2.0)
                            except TimeoutError:
                                child.kill()
                                await child.wait()

                exit_code = child.returncode if child.returncode is not None else -1
                dropped = buffer.dropped
            finally:
                if classifier is not None:
                    await classifier.aclose()

        await storage.end_session(session_id, exit_code=exit_code)
        return ProxyResult(exit_code=exit_code, events_dropped=dropped)
    finally:
        await storage.close()


async def _pump(
    *,
    src: _LineReader,
    dst: _LineWriter,
    reverse_dst: _LineWriter,
    direction: Direction,
    inspector: Inspector | None,
    client_write_lock: asyncio.Lock,
    is_client_target: bool,
    buffer: EventBuffer,
    session_id: int,
    stop_event: asyncio.Event,
) -> None:
    """Copy newline-delimited frames from ``src`` to ``dst``, optionally
    inspecting and substituting them along the way (ADR-0004 §1).

    Parameters
    ----------
    dst
        The "primary" peer for this direction — server stdin for c2s,
        client stdout for s2c.
    reverse_dst
        The other peer. Only used when the inspector decides to BLOCK
        a c2s request and we need to send a synthetic JSON-RPC error
        back to the client (ADR-0004 §5).
    is_client_target
        ``True`` when ``dst`` is the client writer. We hold
        ``client_write_lock`` for every write to a client-bound writer
        so the c2s synthetic-block path cannot interleave with normal
        s2c forwarding.
    """
    try:
        while not stop_event.is_set():
            try:
                line = await src.readline()
            except asyncio.LimitOverrunError as exc:
                consumed = await _drain_oversized(src, exc.consumed)
                _record_raw(
                    buffer,
                    session_id=session_id,
                    direction=direction,
                    raw=consumed.decode("utf-8", errors="replace"),
                    note="line_limit_exceeded",
                )
                if not await _safe_write(
                    dst,
                    consumed,
                    lock=client_write_lock if is_client_target else None,
                ):
                    return
                continue
            except (ConnectionResetError, BrokenPipeError):
                return

            if not line:
                return  # EOF

            decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if not decoded.strip():
                if not await _safe_write(
                    dst,
                    line,
                    lock=client_write_lock if is_client_target else None,
                ):
                    return
                continue

            # Week-3 audit fix: a JSON-RPC batch is one wire frame but
            # several logical messages. We inspect each member separately
            # so the audit log shows per-member verdicts; if ANY member
            # blocks, we replace the entire batch (wrapped as an array
            # to keep JSON-RPC format valid).
            members = split_batch(decoded)
            is_batch = len(members) > 1

            inspections: list[InspectionResult | None] = []
            if inspector is not None:
                for member in members:
                    parsed_msg, _ = parse_frame(member)
                    method_hint: str | None = getattr(parsed_msg, "method", None)
                    insp = await inspector.inspect(
                        raw=member,
                        parsed=parsed_msg,
                        direction=direction,
                        method_hint=method_hint,
                    )
                    inspections.append(insp)
            else:
                inspections = [None] * len(members)

            blocking = next(
                (
                    i
                    for i in inspections
                    if i is not None
                    and i.action == "block"
                    and i.replacement is not None
                ),
                None,
            )

            if blocking is not None:
                if is_batch:
                    # Wrap the single replacement as a 1-element JSON-RPC
                    # batch reply so a strict client parsing the array
                    # still gets a valid response shape.
                    replacement_text = "[" + (blocking.replacement or "") + "]"
                else:
                    replacement_text = blocking.replacement or ""
                replacement_bytes = (replacement_text + "\n").encode("utf-8")

                if direction == "server_to_client":
                    if not await _safe_write(
                        dst, replacement_bytes, lock=client_write_lock
                    ):
                        return
                else:
                    if not await _safe_write(
                        reverse_dst, replacement_bytes, lock=client_write_lock
                    ):
                        return
                    _record_synthetic(
                        buffer,
                        session_id=session_id,
                        raw=blocking.replacement or "",
                        inspection=blocking,
                    )
                _log_per_member(
                    buffer,
                    session_id=session_id,
                    direction=direction,
                    members=members,
                    inspections=inspections,
                )
                continue

            # Normal forward (allow / warn / block-downgraded-to-warn).
            if not await _safe_write(
                dst, line, lock=client_write_lock if is_client_target else None
            ):
                return
            _log_per_member(
                buffer,
                session_id=session_id,
                direction=direction,
                members=members,
                inspections=inspections,
            )
    finally:
        if not dst.is_closing():
            dst.close()


async def _safe_write(
    writer: _LineWriter,
    data: bytes,
    *,
    lock: asyncio.Lock | None,
) -> bool:
    """Write ``data`` through ``writer``, optionally serialised by a lock."""
    if lock is None:
        return await writer.write_line(data)
    async with lock:
        return await writer.write_line(data)


async def _drain_oversized(src: _LineReader, consumed: int) -> bytes:
    """Best-effort drain of an oversized frame.

    Only the asyncio reader exposes ``readexactly``; the blocking fallback
    already returned the partial bytes inside ``LimitOverrunError`` is not
    reachable on that path. We probe via ``getattr`` and degrade gracefully.
    """
    readexactly = getattr(src, "_readexactly", None)
    if readexactly is not None:
        try:
            return cast(bytes, await readexactly(consumed))
        except Exception as exc:
            logger.debug("oversized drain failed: %r", exc)
    return b""


def _log_per_member(
    buffer: EventBuffer,
    *,
    session_id: int,
    direction: Direction,
    members: list[str],
    inspections: list[InspectionResult | None],
) -> None:
    """Log every JSON-RPC member with its own detector verdict.

    Week-3 audit fix: in a batch frame we now have one inspection per
    member instead of one shared verdict. ``members`` and ``inspections``
    must be the same length; the caller (``_pump``) guarantees this by
    deriving both from the same :func:`split_batch` result.
    """
    if len(members) != len(inspections):
        raise ValueError(
            f"_log_per_member: {len(members)} members vs {len(inspections)} "
            "inspections; the caller must provide one per member"
        )
    for member, inspection in zip(members, inspections, strict=True):
        parsed, kind = parse_frame(member)
        record = EventRecord.from_parsed(
            session_id=session_id,
            direction=direction,
            parsed=parsed,
            kind=kind,
            raw=member,
        )
        if inspection is not None:
            record = record.model_copy(
                update={
                    "det_verdict": inspection.verdict,
                    "det_score": inspection.score,
                    "det_rules": (list(inspection.rules_hit) if inspection.rules_hit else None),
                    "det_classifier": inspection.classifier,
                    "det_latency_ms": inspection.latency_ms,
                    "det_action": inspection.action,
                    "note": inspection.note,
                }
            )
        buffer.record(record)


def _record_synthetic(
    buffer: EventBuffer,
    *,
    session_id: int,
    raw: str,
    inspection: InspectionResult,
) -> None:
    """Log a synthetic s2c reply emitted by the proxy on c2s block.

    The synthetic event mirrors the parent c2s block's verdict so
    ``logs --verdict block`` shows BOTH rows; ``note='synthetic-block'``
    marks the row as proxy-emitted rather than from the real server.
    """
    parsed, kind = parse_frame(raw)
    record = EventRecord.from_parsed(
        session_id=session_id,
        direction="server_to_client",
        parsed=parsed,
        kind=kind,
        raw=raw,
    )
    record = record.model_copy(
        update={
            "det_verdict": inspection.verdict,
            "det_score": inspection.score,
            "det_rules": list(inspection.rules_hit) if inspection.rules_hit else None,
            "det_classifier": inspection.classifier,
            "det_latency_ms": inspection.latency_ms,
            "det_action": inspection.action,
            "note": "synthetic-block",
        }
    )
    buffer.record(record)


def _record_raw(
    buffer: EventBuffer,
    *,
    session_id: int,
    direction: Direction,
    raw: str,
    note: str,
) -> None:
    record = EventRecord(
        session_id=session_id,
        direction=direction,
        kind="raw",
        raw=raw,
        note=note,
    )
    buffer.record(record)


# --------------------------------------------------------------------------
# I/O adapters
# --------------------------------------------------------------------------


class _AsyncStreamReader:
    """Wraps :class:`asyncio.StreamReader` as a :class:`_LineReader`."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader

    async def readline(self) -> bytes:
        return await self._reader.readline()

    async def _readexactly(self, n: int) -> bytes:
        return await self._reader.readexactly(n)

    def close(self) -> None:  # readers don't need explicit close
        return


class _AsyncStreamWriter:
    """Wraps :class:`asyncio.StreamWriter` as a :class:`_LineWriter`."""

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self._writer = writer

    async def write_line(self, data: bytes) -> bool:
        try:
            self._writer.write(data)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            return False
        return True

    def close(self) -> None:
        if not self._writer.is_closing():
            self._writer.close()

    async def aclose(self) -> None:
        self.close()
        with suppress(ConnectionResetError, BrokenPipeError, Exception):
            await self._writer.wait_closed()

    def is_closing(self) -> bool:
        return self._writer.is_closing()


class _BlockingReader:
    """Fallback: blocking line reader on a worker thread."""

    def __init__(self, fileobj: IO[bytes]) -> None:
        self._fileobj = fileobj
        self._closed = False

    async def readline(self) -> bytes:
        if self._closed:
            return b""
        return await asyncio.to_thread(self._fileobj.readline)

    def close(self) -> None:
        self._closed = True


class _BlockingWriter:
    """Fallback: blocking line writer on a worker thread.

    We deliberately do **not** close the underlying file object on
    :meth:`close` — that would close real ``sys.stdout`` or ``sys.stderr``
    and break everything else in the process. We just flip a flag.
    """

    def __init__(self, fileobj: IO[bytes]) -> None:
        self._fileobj = fileobj
        self._closed = False
        self._lock = asyncio.Lock()

    async def write_line(self, data: bytes) -> bool:
        if self._closed:
            return False
        async with self._lock:
            try:
                await asyncio.to_thread(self._sync_write, data)
            except (ConnectionResetError, BrokenPipeError):
                self._closed = True
                return False
        return True

    def _sync_write(self, data: bytes) -> None:
        self._fileobj.write(data)
        self._fileobj.flush()

    def close(self) -> None:
        self._closed = True

    async def aclose(self) -> None:
        self._closed = True

    def is_closing(self) -> bool:
        return self._closed


async def _open_client_reader(limit: int) -> _LineReader:
    loop = asyncio.get_running_loop()
    try:
        reader = asyncio.StreamReader(limit=limit, loop=loop)
        protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
        return _AsyncStreamReader(reader)
    except (ValueError, OSError, NotImplementedError) as exc:
        logger.debug("falling back to blocking stdin reader: %r", exc)
        return _BlockingReader(sys.stdin.buffer)


async def _open_client_writer() -> _LineWriter:
    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.connect_write_pipe(
            lambda: asyncio.streams.FlowControlMixin(loop=loop),
            sys.stdout.buffer,
        )
        sw = asyncio.StreamWriter(transport, protocol, None, loop)
        return _AsyncStreamWriter(sw)
    except (ValueError, OSError, NotImplementedError) as exc:
        logger.debug("falling back to blocking stdout writer: %r", exc)
        return _BlockingWriter(sys.stdout.buffer)


def _install_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop_event.set)


async def _patch_session_with_server_pid(
    storage: Storage, session_id: int, server_pid: int | None
) -> None:
    if server_pid is None:
        return
    await storage.set_server_pid(session_id, server_pid)


async def _build_inspector(
    settings: Settings, storage: Storage
) -> tuple[Inspector | None, OllamaClassifier | None]:
    """Construct the Inspector + classifier pair (ADR-0004 §1).

    Returns ``(None, None)`` when ``settings.detector.enabled`` is False —
    the pump then keeps Week 1 behaviour. Otherwise the caller owns the
    classifier and must ``aclose`` it on shutdown.
    """
    det = settings.detector
    if not det.enabled:
        return None, None

    rules = RulesEngine.from_directory(det.rules_dir)
    policy = (
        Policy.from_file(det.policies_file) if det.policies_file is not None else default_policy()
    )

    classifier: OllamaClassifier | None = None
    if det.llm_enabled:
        classifier = OllamaClassifier(
            storage=storage,
            url=det.ollama_url,
            model=det.ollama_model,
            timeout_ms=det.timeout_ms,
            cache_ttl_s=det.cache_ttl_s,
            circuit_threshold=det.circuit_threshold,
            circuit_open_s=det.circuit_open_s,
        )

    inspector = Inspector(
        rules=rules,
        classifier=classifier,
        policy=policy,
        max_latency_ms=det.max_latency_ms,
        short_circuit_threshold=det.short_circuit_threshold,
    )
    logger.info(
        "detector: enabled (rules=%d, llm=%s, policy=%s)",
        len(rules),
        "on" if classifier is not None else "off",
        det.policies_file or "<built-in>",
    )
    return inspector, classifier
