"""Configuration resolution.

Precedence (high → low): CLI flag → env var → config file → built-in default.
Resolution lives here so the CLI and the proxy share one source of truth.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ENV_DB = "MCP_FIREWALL_DB"
ENV_CONFIG = "MCP_FIREWALL_CONFIG"

DEFAULT_DB_RELATIVE = Path("data/log.db")
DEFAULT_QUEUE_MAX = 10_000
DEFAULT_BATCH_SIZE = 100
DEFAULT_BATCH_INTERVAL_MS = 50


@dataclass(frozen=True)
class Settings:
    db_path: Path
    queue_max: int = DEFAULT_QUEUE_MAX
    batch_size: int = DEFAULT_BATCH_SIZE
    batch_interval_ms: int = DEFAULT_BATCH_INTERVAL_MS

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
        cli_db_path
        or os.environ.get(ENV_DB)
        or storage_section.get("db_path")
    )

    if db_path_raw:
        db_path = Path(db_path_raw).expanduser()
    else:
        db_path = _project_root() / DEFAULT_DB_RELATIVE

    return Settings(
        db_path=db_path.resolve(),
        queue_max=int(storage_section.get("queue_max", DEFAULT_QUEUE_MAX)),
        batch_size=int(storage_section.get("batch_size", DEFAULT_BATCH_SIZE)),
        batch_interval_ms=int(storage_section.get("batch_interval_ms", DEFAULT_BATCH_INTERVAL_MS)),
    )
