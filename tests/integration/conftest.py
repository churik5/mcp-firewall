"""Shared helpers for integration tests (Week 3).

Each integration test fixture is a JSON file shipped under
``tests/integration/fixtures/<server>/``. The test pipes the fixture's
contents through ``bulwark run --server cat``: ``cat`` echoes the
bytes back as if they were the server's response, the proxy inspects
the s2c stream, and the test asserts on what reached stdout and on
the audit log.

Why ``cat`` instead of a stub Python server? The proxy's job is to
inspect *bytes that look like JSON-RPC*. The shape of the bytes —
which is what we test — is fixture-driven; the network behaviour of
the upstream server is irrelevant. Keeping ``cat`` removes a layer of
test-only Python.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from bulwark_mcp.storage import Storage

FIXTURES_ROOT = Path(__file__).parent / "fixtures"


def load_fixture(server: str, name: str) -> str:
    """Read ``fixtures/<server>/<name>.json`` and return it as a single
    JSON-RPC line (newline-stripped, separator-compacted).
    """
    path = FIXTURES_ROOT / server / f"{name}.json"
    obj = json.loads(path.read_text(encoding="utf-8"))
    return json.dumps(obj, separators=(",", ":"))


def write_detector_config(path: Path, *, llm_enabled: bool = False) -> None:
    """Write a rules-only detector config so integration tests stay
    deterministic without an Ollama dependency."""
    path.write_text(
        yaml.safe_dump(
            {
                "detector": {
                    "enabled": True,
                    "llm": {"enabled": llm_enabled},
                    "max_latency_ms": 200,
                }
            }
        ),
        encoding="utf-8",
    )


async def run_through_proxy(
    *,
    db_path: Path,
    config_path: Path,
    frames: list[str],
    timeout: float = 8.0,
) -> tuple[int, list[str]]:
    """Run the real CLI as a subprocess and feed it ``frames`` on stdin.

    Returns ``(returncode, forwarded_lines)`` — the lines the proxy
    wrote to stdout (i.e. what an MCP client would see).
    """
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "bulwark_mcp",
        "run",
        "--server",
        "cat",
        "--db-path",
        str(db_path),
        "--config",
        str(config_path),
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
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        pytest.fail("proxy did not exit within the timeout")
    assert proc.returncode is not None
    forwarded = [line for line in stdout.decode().splitlines() if line.strip()]
    return proc.returncode, forwarded


async def read_audit_log(db_path: Path, *, limit: int = 50) -> list[dict[str, Any]]:
    """Read the audit log as a list of plain dicts (one per row).

    Values are typed ``Any`` because aiosqlite.Row mixes int / str / bytes /
    None per column and the tests want to call json.loads on string columns
    without a noisy cast every time.
    """
    async with Storage(db_path) as storage:
        rows = await storage.latest_events(limit=limit)
    return [dict(r) for r in rows]
