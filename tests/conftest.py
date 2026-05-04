"""Shared fixtures for the test suite."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest_asyncio

from mcp_firewall.storage import Storage


@pytest_asyncio.fixture
async def storage(tmp_path: Path) -> AsyncIterator[Storage]:
    """A fresh, opened :class:`Storage` rooted in ``tmp_path``."""
    s = Storage(tmp_path / "log.db")
    await s.open()
    try:
        yield s
    finally:
        await s.close()
