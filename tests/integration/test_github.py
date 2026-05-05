"""Integration tests for the github MCP server (Week 3).

Source for the protocol shapes:
- https://github.com/github/github-mcp-server (read README + the
  ``tools/list`` reply schema; we mirror the ``content`` array shape).

We run smoke + benign + attack against fixtures so we test what an
end-user with `npx -y @modelcontextprotocol/server-github` would
experience.
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


SERVER = "github"


async def test_smoke_handshake_round_trips(tmp_path: Path) -> None:
    """The github MCP server's initialize reply must travel through
    the proxy unchanged when the detector is enabled."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    handshake = load_fixture(SERVER, "handshake")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[handshake])
    assert rc == 0
    assert len(forwarded) == 1
    assert json.loads(forwarded[0]) == json.loads(handshake)


async def test_benign_repo_search_passes_through(tmp_path: Path) -> None:
    """A real-shape ``search_repositories`` result with three benign
    rows is forwarded as-is, with PASS verdict in the audit log."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    benign = load_fixture(SERVER, "benign_repo_search")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[benign])
    assert rc == 0
    assert len(forwarded) == 1
    assert json.loads(forwarded[0]) == json.loads(benign)

    rows = await read_audit_log(db)
    s2c = next(r for r in rows if r["direction"] == "server_to_client")
    assert s2c["det_verdict"] == "PASS"


async def test_attack_in_issue_body_is_blocked(tmp_path: Path) -> None:
    """A tool result containing a role-hijack + exfiltration payload
    in an issue body must be replaced with a sanitised reply."""
    db = tmp_path / "log.db"
    cfg = tmp_path / "cfg.yaml"
    write_detector_config(cfg)

    attack = load_fixture(SERVER, "attack_in_issue_body")
    rc, forwarded = await run_through_proxy(db_path=db, config_path=cfg, frames=[attack])
    assert rc == 0
    received = json.loads(forwarded[0])
    assert received["id"] == 9
    assert received["result"]["isError"] is True
    text = received["result"]["content"][0]["text"]
    assert "bulwark-mcp blocked" in text
    # Attacker payload must NOT survive into the agent-bound reply.
    assert "attacker.example.com" not in text
    assert "credentials" not in text

    rows = await read_audit_log(db)
    s2c = next(r for r in rows if r["direction"] == "server_to_client")
    assert s2c["det_verdict"] == "BLOCK"
    rules_hit = json.loads(s2c["det_rules"])
    # Both role-hijack and exfiltration patterns should fire.
    assert any(r.startswith("role_hijack") for r in rules_hit)
    assert any(r.startswith("exfil") for r in rules_hit)
