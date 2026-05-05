"""Integration tests for the brave-search MCP server.

Source: https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search

The headline threat for a search-MCP is *snippet poisoning*: an
attacker plants prompt-injection text in a page that ranks for a
benign query. The proxy must catch it on the s2c hop.
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


SERVER = "brave_search"


async def test_smoke_handshake_round_trips(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    frame = load_fixture(SERVER, "handshake")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[frame])
    assert rc == 0
    assert json.loads(forwarded[0]) == json.loads(frame)


async def test_benign_search_passes_through(tmp_path: Path) -> None:
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    benign = load_fixture(SERVER, "benign_search")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[benign])
    assert rc == 0
    assert json.loads(forwarded[0]) == json.loads(benign)

    rows = await read_audit_log(db)
    s2c = next(r for r in rows if r["direction"] == "server_to_client")
    assert s2c["det_verdict"] == "PASS"


async def test_attack_in_search_snippet_is_blocked(tmp_path: Path) -> None:
    """Snippet poisoning: an attacker-controlled search result tries to
    pivot the agent. The proxy must replace it before the agent reads it."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    attack = load_fixture(SERVER, "attack_in_search_snippet")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[attack])
    assert rc == 0
    received = json.loads(forwarded[0])
    assert received["result"]["isError"] is True
    text = received["result"]["content"][0]["text"]
    assert "attacker.example.com" not in text
    assert "shell commands" not in text

    rows = await read_audit_log(db)
    s2c = next(r for r in rows if r["direction"] == "server_to_client")
    assert s2c["det_verdict"] == "BLOCK"
    rules_hit = json.loads(s2c["det_rules"])
    # The 'from now on' / 'new instructions' / send-to-url combo: at
    # least one role-hijack and one exfiltration rule should fire.
    assert any(r.startswith("role_hijack") for r in rules_hit)
    assert any(r.startswith("exfil") for r in rules_hit)
