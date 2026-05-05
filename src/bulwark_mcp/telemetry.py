"""Opt-in anonymous telemetry (ADR-0005 §3).

Privacy posture, in priority order:

1. **Off by default.** Only the env var ``BULWARK_TELEMETRY=true``
   turns it on. There is no CLI flag and no config-file flip — making
   this a deliberate, machine-level choice rather than a one-shot
   accident.
2. **Local log first.** Every payload is appended to
   ``<db-dir>/telemetry.log`` *before* the HTTP call. Network errors
   never erase the log entry. The user can ``cat`` the log any time
   to see exactly what was sent.
3. **Silent fail on network errors.** Telemetry must never block, slow,
   or crash the proxy. Every HTTP call is wrapped in a 5 s timeout
   and a broad ``except`` that records the error to the log and moves
   on.
4. **No traffic content.** The payload contains version, OS, Python
   version, days-since-install, and four integer event counts. No
   rule names, no method names, no server commands, no IPs.

Cadence:

- First send 60 s after the proxy starts (debounces flapping restarts).
- A second send if the process is still alive 24 h later, then every
  24 h thereafter.
- No persistent queue — if the network is down, that day's data is lost.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import sys
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import httpx

from . import __version__
from .config import Settings
from .stats import compute_stats
from .storage import Storage

logger = logging.getLogger(__name__)

TELEMETRY_SCHEMA_VERSION: Final[int] = 1
DEFAULT_ENDPOINT: Final[str] = "https://telemetry.example.com/v1/ingest"
ENV_ENABLED: Final[str] = "BULWARK_TELEMETRY"
ENV_URL: Final[str] = "BULWARK_TELEMETRY_URL"

_TRUTHY: Final[frozenset[str]] = frozenset(("true", "1", "yes", "on"))

_RELEASE_MAJOR_RE: Final[re.Pattern[str]] = re.compile(r"^(\d+)")


def _major_release(release: str) -> str:
    """Reduce ``platform.release()`` to its first numeric component.

    Linux can return strings like ``5.4.0-foo-bar`` or
    ``6.5.0-1024-azure`` that uniquely identify a custom kernel build.
    Only the major version is meaningful for product analytics.
    Returns ``""`` if no leading digit is found (uncommon).
    """
    if not release:
        return ""
    match = _RELEASE_MAJOR_RE.match(release)
    return match.group(1) if match else ""


@dataclass(frozen=True)
class _Identity:
    id: str
    first_seen_at: datetime


def is_enabled() -> bool:
    """Read ``BULWARK_TELEMETRY`` and return whether to opt in.

    Anything but truthy values (``true|1|yes|on``, case-insensitive)
    leaves telemetry off — including unset, empty, and ``false``.
    """
    return os.environ.get(ENV_ENABLED, "").strip().lower() in _TRUTHY


def endpoint_url() -> str:
    """Resolved endpoint URL.

    ``BULWARK_TELEMETRY_URL=disabled`` is a deliberate kill-switch
    that skips the HTTP call but still writes the local log — useful
    for offline development or for users who want to inspect what
    *would* be sent.
    """
    return os.environ.get(ENV_URL, DEFAULT_ENDPOINT).strip() or DEFAULT_ENDPOINT


class TelemetryClient:
    """Async helper that builds + transmits one payload.

    The client is cheap; it's safe to construct one per process and
    discard. ``aclose`` must be awaited before exit so the underlying
    httpx client shuts cleanly.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        installation_path: Path | None = None,
        log_path: Path | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_s: float = 5.0,
        stderr_writer: Any = sys.stderr,
    ) -> None:
        self._settings = settings
        data_dir = settings.db_path.parent
        self._installation_path = installation_path or (data_dir / "installation_id")
        self._log_path = log_path or (data_dir / "telemetry.log")
        self._http = httpx.AsyncClient(
            timeout=timeout_s,
            transport=transport,
        )
        self._banner_shown = False
        self._stderr = stderr_writer

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Identity (installation_id + first_seen_at)
    # ------------------------------------------------------------------

    def _identity(self) -> _Identity:
        """Read the installation file or create one on first use."""
        if self._installation_path.exists():
            try:
                data = json.loads(self._installation_path.read_text(encoding="utf-8"))
                return _Identity(
                    id=str(data["id"]),
                    first_seen_at=datetime.fromisoformat(str(data["first_seen_at"])),
                )
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                # File present but unreadable — re-mint it. Better than crashing.
                logger.warning("telemetry: installation_id file unreadable; regenerating")
        identity = _Identity(id=str(uuid.uuid4()), first_seen_at=datetime.now(UTC))
        self._installation_path.parent.mkdir(parents=True, exist_ok=True)
        self._installation_path.write_text(
            json.dumps(
                {
                    "id": identity.id,
                    "first_seen_at": identity.first_seen_at.isoformat(),
                }
            ),
            encoding="utf-8",
        )
        # Audit fix: keep installation_id readable only to the running user
        # so a co-tenant on a shared machine can't correlate installs.
        with suppress(OSError):
            os.chmod(self._installation_path, 0o600)
        return identity

    # ------------------------------------------------------------------
    # Payload assembly
    # ------------------------------------------------------------------

    async def build_payload(self, storage: Storage) -> dict[str, Any]:
        """Build the daily snapshot payload (last 24 h)."""
        stats = await compute_stats(storage, since=timedelta(days=1))
        identity = self._identity()
        days_active = max(
            0,
            int((datetime.now(UTC) - identity.first_seen_at) / timedelta(days=1)),
        )
        return {
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "installation_id": identity.id,
            "version": __version__,
            "platform": platform.system().lower(),
            # Only the major-version digit — the full release string can leak
            # custom kernel build identifiers (e.g. "5.4.0-foo-bar"); see the
            # Week-3 audit report.
            "platform_release": _major_release(platform.release()),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "days_active": days_active,
            "events_total": stats.total_events,
            "events_blocked": stats.verdicts.get("BLOCK", 0),
            "events_warned": stats.verdicts.get("WARN", 0),
            "events_passed": stats.verdicts.get("PASS", 0),
            "detector_enabled": self._settings.detector.enabled,
        }

    # ------------------------------------------------------------------
    # Transmission
    # ------------------------------------------------------------------

    def show_banner_once(self) -> None:
        if self._banner_shown:
            return
        self._banner_shown = True
        url = endpoint_url()
        self._stderr.write(
            "Telemetry enabled. Will send anonymous usage stats to "
            f"{url} daily.\n"
            "Payload: version, OS, Python version, event counts.\n"
            "Disable: unset BULWARK_TELEMETRY or set to false.\n"
            "See docs/OBSERVABILITY.md for full payload schema.\n"
        )
        with suppress(Exception):
            self._stderr.flush()

    async def send(self, payload: dict[str, Any]) -> str:
        """Send ``payload`` to the configured endpoint.

        Returns a short status string (``"ok"``, ``"disabled-by-config"``,
        or ``"error:<ExceptionName>"``). Always writes the same status
        to the local log before returning.
        """
        url = endpoint_url()
        if url == "disabled":
            self._append_log(payload, "disabled-by-config")
            return "disabled-by-config"

        try:
            response = await self._http.post(url, json=payload)
            response.raise_for_status()
        except Exception as exc:
            err = f"error:{type(exc).__name__}"
            self._append_log(payload, err, message=str(exc))
            return err

        self._append_log(payload, "ok")
        return "ok"

    def _append_log(
        self,
        payload: dict[str, Any],
        status: str,
        *,
        message: str | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "status": status,
            "payload": payload,
        }
        if message is not None:
            record["error_message"] = message
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            existed = self._log_path.exists()
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            if not existed:
                # Audit fix: keep telemetry.log readable only to the running
                # user. We chmod once on creation; on append, the existing
                # mode is preserved.
                with suppress(OSError):
                    os.chmod(self._log_path, 0o600)
        except OSError as exc:
            logger.warning("telemetry: failed to append log entry: %r", exc)
