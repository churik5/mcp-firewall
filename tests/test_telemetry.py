"""Tests for the opt-in telemetry sender (Week 3, ADR-0005 §3).

These tests never touch a real HTTP endpoint — every transmission goes
through :class:`httpx.MockTransport` that records what would have been
sent.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from bulwark_mcp.config import DetectorSettings, Settings
from bulwark_mcp.storage import Storage
from bulwark_mcp.telemetry import (
    DEFAULT_ENDPOINT,
    ENV_ENABLED,
    ENV_URL,
    TELEMETRY_SCHEMA_VERSION,
    TelemetryClient,
    endpoint_url,
    is_enabled,
)

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(ENV_ENABLED, raising=False)
    monkeypatch.delenv(ENV_URL, raising=False)
    yield


def _settings_in(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "log.db",
        detector=DetectorSettings(enabled=True),
    )


def _record_handler(captured: list[httpx.Request]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(204)

    return handler


# ---------------------------------------------------------------------
# Env handling
# ---------------------------------------------------------------------


class TestEnvHandling:
    @pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on"])
    def test_truthy_values_enable(
        self, monkeypatch: pytest.MonkeyPatch, value: str, clean_env: None
    ) -> None:
        monkeypatch.setenv(ENV_ENABLED, value)
        assert is_enabled()

    @pytest.mark.parametrize("value", ["", "false", "0", "no", "off", "maybe"])
    def test_non_truthy_values_disable(
        self, monkeypatch: pytest.MonkeyPatch, value: str, clean_env: None
    ) -> None:
        if value == "":
            # Empty value is the "set but empty" case; setenv with "" works.
            monkeypatch.setenv(ENV_ENABLED, value)
        else:
            monkeypatch.setenv(ENV_ENABLED, value)
        assert not is_enabled()

    def test_unset_disables(self, monkeypatch: pytest.MonkeyPatch, clean_env: None) -> None:
        assert not is_enabled()

    def test_default_endpoint(self, clean_env: None) -> None:
        assert endpoint_url() == DEFAULT_ENDPOINT

    def test_endpoint_override(self, monkeypatch: pytest.MonkeyPatch, clean_env: None) -> None:
        monkeypatch.setenv(ENV_URL, "https://my-self-hosted.example/v1")
        assert endpoint_url() == "https://my-self-hosted.example/v1"

    def test_endpoint_disabled_keeps_local_log_only(
        self, monkeypatch: pytest.MonkeyPatch, clean_env: None
    ) -> None:
        monkeypatch.setenv(ENV_URL, "disabled")
        assert endpoint_url() == "disabled"


# ---------------------------------------------------------------------
# Identity (installation_id + first_seen_at)
# ---------------------------------------------------------------------


class TestIdentity:
    async def test_first_run_creates_identity_file(self, tmp_path: Path, clean_env: None) -> None:
        client = TelemetryClient(settings=_settings_in(tmp_path))
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
        finally:
            await client.aclose()
        identity_path = tmp_path / "installation_id"
        assert identity_path.exists()
        data = json.loads(identity_path.read_text(encoding="utf-8"))
        assert data["id"] == payload["installation_id"]
        assert "first_seen_at" in data

    async def test_identity_is_stable_across_calls(self, tmp_path: Path, clean_env: None) -> None:
        client = TelemetryClient(settings=_settings_in(tmp_path))
        try:
            async with Storage(tmp_path / "log.db") as storage:
                a = await client.build_payload(storage)
                b = await client.build_payload(storage)
        finally:
            await client.aclose()
        assert a["installation_id"] == b["installation_id"]

    async def test_corrupt_identity_file_is_regenerated(
        self, tmp_path: Path, clean_env: None
    ) -> None:
        # tmp_path is provided by pytest and always exists; corrupt the
        # identity file before TelemetryClient sees it.
        identity_path = tmp_path / "installation_id"
        identity_path.write_text("{not-json", encoding="utf-8")

        client = TelemetryClient(settings=_settings_in(tmp_path))
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
        finally:
            await client.aclose()
        # Old file replaced; new id is a UUID.
        new = json.loads(identity_path.read_text(encoding="utf-8"))
        assert new["id"] == payload["installation_id"]


# ---------------------------------------------------------------------
# Payload contents
# ---------------------------------------------------------------------


class TestPayload:
    async def test_payload_has_no_rule_names_or_traffic_content(
        self, tmp_path: Path, clean_env: None
    ) -> None:
        client = TelemetryClient(settings=_settings_in(tmp_path))
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
        finally:
            await client.aclose()
        # Privacy contract — these fields MUST NOT appear.
        forbidden = (
            "top_rules",
            "rules",
            "method",
            "raw",
            "params",
            "result",
            "tool_args",
            "ip",
            "host",
            "hostname",
            "server_command",
        )
        for key in forbidden:
            assert key not in payload, f"telemetry payload leaked forbidden key {key!r}"

    async def test_payload_has_required_minimal_fields(
        self, tmp_path: Path, clean_env: None
    ) -> None:
        client = TelemetryClient(settings=_settings_in(tmp_path))
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
        finally:
            await client.aclose()
        assert payload["schema_version"] == TELEMETRY_SCHEMA_VERSION
        assert isinstance(payload["installation_id"], str)
        assert isinstance(payload["version"], str)
        assert isinstance(payload["platform"], str)
        assert isinstance(payload["python_version"], str)
        assert payload["events_total"] == 0
        assert payload["events_blocked"] == 0
        assert payload["events_warned"] == 0
        assert payload["events_passed"] == 0
        assert payload["detector_enabled"] is True


# ---------------------------------------------------------------------
# Transmission + local log
# ---------------------------------------------------------------------


class TestTransmission:
    async def test_send_logs_locally_before_http_attempt(
        self, tmp_path: Path, clean_env: None
    ) -> None:
        captured: list[httpx.Request] = []
        client = TelemetryClient(
            settings=_settings_in(tmp_path),
            transport=httpx.MockTransport(_record_handler(captured)),
        )
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
                status = await client.send(payload)
        finally:
            await client.aclose()

        assert status == "ok"
        log_path = tmp_path / "telemetry.log"
        assert log_path.exists()
        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["status"] == "ok"
        assert record["payload"]["installation_id"] == payload["installation_id"]
        # And the HTTP call actually happened.
        assert len(captured) == 1
        assert captured[0].url.host == "telemetry.example.com"

    async def test_http_error_is_logged_and_returns_error(
        self, tmp_path: Path, clean_env: None
    ) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        client = TelemetryClient(
            settings=_settings_in(tmp_path),
            transport=httpx.MockTransport(handler),
        )
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
                status = await client.send(payload)
        finally:
            await client.aclose()

        assert status.startswith("error:")
        log = (tmp_path / "telemetry.log").read_text(encoding="utf-8")
        assert "error:" in log

    async def test_connection_failure_is_silent(self, tmp_path: Path, clean_env: None) -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        client = TelemetryClient(
            settings=_settings_in(tmp_path),
            transport=httpx.MockTransport(handler),
        )
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
                status = await client.send(payload)
        finally:
            await client.aclose()
        assert status == "error:ConnectError"

    async def test_disabled_endpoint_skips_http_keeps_log(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
    ) -> None:
        monkeypatch.setenv(ENV_URL, "disabled")
        captured: list[httpx.Request] = []
        client = TelemetryClient(
            settings=_settings_in(tmp_path),
            transport=httpx.MockTransport(_record_handler(captured)),
        )
        try:
            async with Storage(tmp_path / "log.db") as storage:
                payload = await client.build_payload(storage)
                status = await client.send(payload)
        finally:
            await client.aclose()
        assert status == "disabled-by-config"
        assert captured == []
        # Local log still recorded the would-be payload.
        log = (tmp_path / "telemetry.log").read_text(encoding="utf-8")
        assert "disabled-by-config" in log


# ---------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------


class TestBanner:
    async def test_banner_lists_endpoint_and_disable_instruction(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
    ) -> None:
        monkeypatch.setenv(ENV_URL, "https://my.example/v1")
        sink = io.StringIO()
        client = TelemetryClient(settings=_settings_in(tmp_path), stderr_writer=sink)
        try:
            client.show_banner_once()
            client.show_banner_once()  # second call must be silent
        finally:
            await client.aclose()
        out = sink.getvalue()
        assert out.count("Telemetry enabled") == 1
        assert "https://my.example/v1" in out
        assert "BULWARK_TELEMETRY" in out
        assert "OBSERVABILITY.md" in out
