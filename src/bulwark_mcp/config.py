"""Configuration resolution.

Precedence (high → low): CLI flag → env var → config file → built-in default.
Resolution lives here so the CLI and the proxy share one source of truth.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ENV_DB = "BULWARK_DB"
ENV_CONFIG = "BULWARK_CONFIG"

DEFAULT_DB_RELATIVE = Path("data/log.db")
DEFAULT_QUEUE_MAX = 10_000
DEFAULT_BATCH_SIZE = 100
DEFAULT_BATCH_INTERVAL_MS = 50


_DEFAULT_BUILTIN_RULES = Path(__file__).resolve().parent / "rules" / "builtin"


@dataclass(frozen=True)
class DetectorSettings:
    """Detection-layer knobs (ADR-0004).

    Defaults are intentionally OFF for v0.2 — Week 1 users are not
    surprised by added latency until they explicitly opt in.
    """

    enabled: bool = False
    rules_dir: Path = field(default=_DEFAULT_BUILTIN_RULES)
    llm_enabled: bool = True
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    timeout_ms: int = 1000
    cache_ttl_s: int = 86400
    circuit_threshold: int = 3
    circuit_open_s: int = 60
    policies_file: Path | None = None
    max_latency_ms: int = 200
    short_circuit_threshold: float = 0.9


@dataclass(frozen=True)
class Settings:
    db_path: Path
    queue_max: int = DEFAULT_QUEUE_MAX
    batch_size: int = DEFAULT_BATCH_SIZE
    batch_interval_ms: int = DEFAULT_BATCH_INTERVAL_MS
    detector: DetectorSettings = field(default_factory=DetectorSettings)

    @property
    def batch_interval_s(self) -> float:
        return self.batch_interval_ms / 1000.0


def _project_root() -> Path:
    """Return a sensible "project root" for the default DB path.

    We walk up from the current working directory looking for a marker
    (``pyproject.toml`` or ``.git``). If none is found we fall back to the
    cwd, which is fine for the bundled E2E test.
    """
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if (parent / "pyproject.toml").is_file() or (parent / ".git").is_dir():
            return parent
    return cwd


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Config file {path} must be a YAML mapping at the top level")
    return loaded


def resolve_settings(
    *,
    cli_db_path: str | os.PathLike[str] | None = None,
    cli_config: str | os.PathLike[str] | None = None,
    cli_detector_enabled: bool | None = None,
    cli_policies: str | os.PathLike[str] | None = None,
) -> Settings:
    """Apply the precedence rules and return final Settings.

    The function never reads the environment more than once; tests can pass
    explicit overrides instead of monkey-patching ``os.environ``.
    """
    file_data: dict[str, Any] = {}
    config_path = cli_config or os.environ.get(ENV_CONFIG)
    if config_path:
        file_data = _load_yaml(Path(config_path))

    storage_section = file_data.get("storage", {}) if isinstance(file_data, dict) else {}
    if not isinstance(storage_section, dict):
        storage_section = {}

    db_path_raw: str | os.PathLike[str] | None = (
        cli_db_path or os.environ.get(ENV_DB) or storage_section.get("db_path")
    )

    if db_path_raw:
        db_path = Path(db_path_raw).expanduser()
    else:
        db_path = _project_root() / DEFAULT_DB_RELATIVE

    detector_section = file_data.get("detector", {}) if isinstance(file_data, dict) else {}
    if not isinstance(detector_section, dict):
        detector_section = {}
    detector = _resolve_detector(
        detector_section,
        cli_enabled=cli_detector_enabled,
        cli_policies=cli_policies,
    )

    return Settings(
        db_path=db_path.resolve(),
        queue_max=int(storage_section.get("queue_max", DEFAULT_QUEUE_MAX)),
        batch_size=int(storage_section.get("batch_size", DEFAULT_BATCH_SIZE)),
        batch_interval_ms=int(storage_section.get("batch_interval_ms", DEFAULT_BATCH_INTERVAL_MS)),
        detector=detector,
    )


def _resolve_detector(
    section: dict[str, Any],
    *,
    cli_enabled: bool | None,
    cli_policies: str | os.PathLike[str] | None,
) -> DetectorSettings:
    """Build a :class:`DetectorSettings` from the YAML detector section.

    CLI flags override file values. Unknown keys in the section are
    ignored (forward-compat).
    """
    llm_section = section.get("llm", {})
    if not isinstance(llm_section, dict):
        llm_section = {}

    enabled = cli_enabled if cli_enabled is not None else bool(section.get("enabled", False))

    rules_dir_raw = section.get("rules_dir")
    rules_dir = Path(rules_dir_raw).expanduser() if rules_dir_raw else _DEFAULT_BUILTIN_RULES

    policies_raw = cli_policies or section.get("policies_file")
    policies_file = Path(policies_raw).expanduser() if policies_raw else None

    return DetectorSettings(
        enabled=enabled,
        rules_dir=rules_dir,
        llm_enabled=bool(llm_section.get("enabled", True)),
        ollama_url=str(llm_section.get("url", "http://localhost:11434")),
        ollama_model=str(llm_section.get("model", "qwen2.5:3b")),
        timeout_ms=int(llm_section.get("timeout_ms", 1000)),
        cache_ttl_s=int(llm_section.get("cache_ttl_s", 86400)),
        circuit_threshold=int(llm_section.get("circuit_threshold", 3)),
        circuit_open_s=int(llm_section.get("circuit_open_s", 60)),
        policies_file=policies_file,
        max_latency_ms=int(section.get("max_latency_ms", 200)),
        short_circuit_threshold=float(section.get("short_circuit_threshold", 0.9)),
    )
