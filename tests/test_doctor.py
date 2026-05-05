"""Tests for the `bulwark doctor` checks (Week 4)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import httpx
import pytest

from bulwark_mcp.config import DetectorSettings, Settings
from bulwark_mcp.doctor import (
    CheckResult,
    _check_db,
    _check_ollama,
    _check_python,
    _check_rules_and_policy,
    overall_status,
    run_checks,
)


def _settings_in(tmp_path: Path, **detector_overrides: object) -> Settings:
    return Settings(
        db_path=tmp_path / "log.db",
        detector=DetectorSettings(enabled=True, **detector_overrides),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------
# Python check
# ---------------------------------------------------------------------


class TestPythonCheck:
    def test_passes_on_311_or_newer(self) -> None:
        # We're running on the supported interpreter — should pass.
        result = _check_python()
        assert result.status == "pass"
        assert "running" in result.detail

    def test_fails_on_old_python(self) -> None:
        # Patch sys.version_info to simulate a 3.10 install.
        with mock.patch.object(sys, "version_info", (3, 10, 7, "final", 0)):
            result = _check_python()
        assert result.status == "fail"
        assert ">= 3.11" in result.detail
        assert result.suggestion is not None


# ---------------------------------------------------------------------
# Ollama check
# ---------------------------------------------------------------------


class TestOllamaCheck:
    async def test_warn_when_llm_disabled(self, tmp_path: Path) -> None:
        settings = _settings_in(tmp_path, llm_enabled=False)
        result = await _check_ollama(settings)
        assert result.status == "warn"
        assert "rules-only" in result.detail

    async def test_warn_when_unreachable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def boom_get(self: object, url: str) -> httpx.Response:
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx.AsyncClient, "get", boom_get)
        settings = _settings_in(tmp_path)
        result = await _check_ollama(settings)
        assert result.status == "warn"
        assert "cannot reach" in result.detail
        assert "ollama serve" in (result.suggestion or "")

    async def test_warn_when_model_not_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get(self: object, url: str) -> httpx.Response:
            return httpx.Response(
                200,
                json={"models": [{"name": "other:1b"}]},
                request=httpx.Request("GET", url),
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
        settings = _settings_in(tmp_path)
        result = await _check_ollama(settings)
        assert result.status == "warn"
        assert "is not pulled" in result.detail

    async def test_pass_when_model_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings_in(tmp_path)
        model = settings.detector.ollama_model

        async def fake_get(self: object, url: str) -> httpx.Response:
            return httpx.Response(
                200,
                json={"models": [{"name": model}]},
                request=httpx.Request("GET", url),
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
        result = await _check_ollama(settings)
        assert result.status == "pass"
        assert "loaded" in result.detail


# ---------------------------------------------------------------------
# DB check
# ---------------------------------------------------------------------


class TestDbCheck:
    async def test_pass_on_fresh_db(self, tmp_path: Path) -> None:
        settings = _settings_in(tmp_path)
        result = await _check_db(settings)
        assert result.status == "pass"
        assert "schema version 2" in result.detail

    async def test_fail_when_dir_unwritable(self, tmp_path: Path) -> None:
        # Path that can't be created — POSIX root requires escalated privs.
        bad = Path("/proc/locked/log.db")
        settings = Settings(
            db_path=bad,
            detector=DetectorSettings(enabled=True),
        )
        result = await _check_db(settings)
        assert result.status == "fail"


# ---------------------------------------------------------------------
# Rules + policy check
# ---------------------------------------------------------------------


class TestRulesPolicyCheck:
    async def test_pass_with_built_in_pack(self, tmp_path: Path) -> None:
        settings = _settings_in(tmp_path)
        result = await _check_rules_and_policy(settings)
        assert result.status == "pass"
        assert "rules loaded" in result.detail
        assert "<built-in>" in result.detail

    async def test_fail_with_broken_rules_dir(self, tmp_path: Path) -> None:
        bad_rules = tmp_path / "broken_rules"
        bad_rules.mkdir()
        (bad_rules / "bad.yaml").write_text(
            "rules:\n  - id: bad\n    pattern: '['\n",
            encoding="utf-8",
        )
        settings = Settings(
            db_path=tmp_path / "log.db",
            detector=DetectorSettings(enabled=True, rules_dir=bad_rules),
        )
        result = await _check_rules_and_policy(settings)
        assert result.status == "fail"
        assert "error" in result.detail.lower()

    async def test_fail_with_broken_policies_file(self, tmp_path: Path) -> None:
        broken = tmp_path / "policies.yaml"
        broken.write_text(
            "rules:\n  - name: kill\n    when: {}\n    action: block\n",
            encoding="utf-8",
        )
        settings = Settings(
            db_path=tmp_path / "log.db",
            detector=DetectorSettings(enabled=True, policies_file=broken),
        )
        result = await _check_rules_and_policy(settings)
        assert result.status == "fail"
        assert "policy" in result.detail.lower()


# ---------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------


class TestAggregate:
    def test_overall_status_picks_worst(self) -> None:
        passing = CheckResult(name="a", status="pass", detail="")
        warning = CheckResult(name="b", status="warn", detail="")
        failing = CheckResult(name="c", status="fail", detail="")
        assert overall_status([passing]) == "pass"
        assert overall_status([passing, warning]) == "warn"
        assert overall_status([warning, failing]) == "fail"

    async def test_run_checks_returns_in_order(self, tmp_path: Path) -> None:
        settings = _settings_in(tmp_path, llm_enabled=False)
        results = await run_checks(settings)
        # Order is documented: python, ollama, db, rules+policy.
        names = [r.name for r in results]
        assert names == ["Python version", "Ollama", "Audit log DB", "Rules + policy"]
