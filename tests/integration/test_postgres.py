"""Integration tests for the postgres MCP server.

Source: https://github.com/modelcontextprotocol/servers/tree/main/src/postgres

The headline threat for a database-MCP is *stored injection*: an
attacker writes a payload into a TEXT column (e.g. a feedback or
comment field). When the agent later runs a benign query that
includes that column, the row is serialised into the tool result and
becomes an injection vector.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from .conftest import (
    load_fixture,
    read_audit_log,
    run_through_proxy,
    write_detector_config,
)

pytestmark = pytest.mark.asyncio


SERVER = "postgres"


async def test_smoke_handshake_round_trips(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    frame = load_fixture(SERVER, "handshake")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[frame])
    assert rc == 0
    assert json.loads(forwarded[0]) == json.loads(frame)


async def test_benign_query_result_passes_through(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    benign = load_fixture(SERVER, "benign_query_result")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[benign])
    assert rc == 0
    assert json.loads(forwarded[0]) == json.loads(benign)

    rows = await read_audit_log(db)
    s2c = next(r for r in rows if r["direction"] == "server_to_client")
    assert s2c["det_verdict"] == "PASS"


async def test_stored_attack_in_text_column_is_blocked(tmp_path: Path) -> None:
    """A row whose TEXT column contains a role-hijack payload must be
    sanitised before reaching the agent."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    attack = load_fixture(SERVER, "attack_in_text_column")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[attack])
    assert rc == 0
    received = json.loads(forwarded[0])
    assert received["result"]["isError"] is True
    text = received["result"]["content"][0]["text"]
    assert "credentials" not in text

    rows = await read_audit_log(db)
    s2c = next(r for r in rows if r["direction"] == "server_to_client")
    assert s2c["det_verdict"] == "BLOCK"
    rules_hit = json.loads(s2c["det_rules"])
    assert any(r.startswith("role_hijack") for r in rules_hit)
