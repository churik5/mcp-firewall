"""Tests for the command-line interface."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from bulwark_mcp import cli
from bulwark_mcp.detectors.base import ClassifierResult


class _UnreachableOllama:
    def __init__(self, **_: object) -> None:
        pass

    async def classify(self, _text: str) -> ClassifierResult:
        return ClassifierResult(reason="error:ConnectError")

    async def aclose(self) -> None:
        pass


def test_detect_reports_friendly_error_when_ollama_is_unreachable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BULWARK_DB", str(tmp_path / "log.db"))
    monkeypatch.setattr(cli, "OllamaClassifier", _UnreachableOllama)

    text = "This benign tool result is intentionally long enough to require LLM classification."
    result = CliRunner().invoke(cli.main, ["detect", text])
    output = result.output + getattr(result, "stderr", "")

    assert result.exit_code == 2
    assert "Could not reach Ollama at http://localhost:11434/." in output
    assert "ollama serve" in output
    assert "ollama pull qwen2.5:3b" in output
    assert "--no-llm" in output
    assert "bulwark doctor" in output
    assert "Traceback" not in output
