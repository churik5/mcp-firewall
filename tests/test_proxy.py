"""End-to-end test for the proxy.

We launch ``python -m bulwark_mcp run --server "cat"`` as a subprocess so
the test exercises the *real* CLI entry point, not just internal helpers.
``cat`` is a poor-man's MCP server — it echoes everything we send back to
stdout, so we can assert on round-trip behaviour and on what landed in the
audit log.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from bulwark_mcp.storage import Storage

pytestmark = pytest.mark.asyncio


async def _run_proxy_subprocess(
    *,
    db_path: Path,
    server_cmd: str,
    frames: list[str],
    timeout: float = 8.0,
) -> tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "bulwark_mcp",
        "run",
        "--server",
        server_cmd,
        "--db-path",
        str(db_path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdin is not None
    payload = "\n".join(frames).encode() + b"\n"
    proc.stdin.write(payload)
    await proc.stdin.drain()
    proc.stdin.close()
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        pytest.fail("proxy did not exit within the timeout")
    assert proc.returncode is not None
    return proc.returncode, stdout, stderr


async def test_round_trips_three_frames_and_persists_both_directions(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    frames = [
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
    ]
    rc, stdout, _ = await _run_proxy_subprocess(db_path=db, server_cmd="cat", frames=frames)
    assert rc == 0

    forwarded = stdout.decode().splitlines()
    assert len(forwarded) == 3
    for line, original in zip(forwarded, frames, strict=True):
        assert json.loads(line) == json.loads(original)

    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=20)
    methods = [r["method"] for r in rows]
    directions = [r["direction"] for r in rows]
    assert methods == [
        "ping",
        "notifications/initialized",
        "tools/list",
        "ping",
        "notifications/initialized",
        "tools/list",
    ]
    assert directions[:3] == ["client_to_server"] * 3
    assert directions[3:] == ["server_to_client"] * 3


async def test_invalid_json_is_logged_as_parse_error_not_dropped(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    frames = ["not-valid-json", '{"jsonrpc":"2.0","id":1,"method":"ping"}']
    rc, _, _ = await _run_proxy_subprocess(db_path=db, server_cmd="cat", frames=frames)
    assert rc == 0
    async with Storage(db) as storage:
        rows = await storage.latest_events(limit=20)
    kinds = [r["kind"] for r in rows]
    assert "parse_error" in kinds
    # The valid frame must still appear in both directions
    assert kinds.count("request") == 2
