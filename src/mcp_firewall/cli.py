"""Command-line interface for mcp-firewall."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

import aiosqlite
import click
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import Settings, resolve_settings
from .proxy import run_proxy
from .storage import Storage, stream_events

# All diagnostic output goes to stderr — stdout is reserved for JSON-RPC frames
# while ``run`` is active.
_console = Console(stderr=True)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, package_name="mcp-firewall")
def main() -> None:
    """mcp-firewall — prompt-injection firewall for MCP servers."""


@main.command("run")
@click.option(
    "--server",
    required=True,
    help='Full command for the underlying MCP server, e.g. "npx -y @mcp/server-filesystem /tmp".',
)
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the audit log location.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase diagnostic verbosity (-v: INFO, -vv: DEBUG).",
)
def cmd_run(
    server: str,
    db_path: Path | None,
    config: Path | None,
    verbose: int,
) -> None:
    """Run the proxy. The MCP client (e.g. Claude Desktop) invokes this."""
    _setup_logging(verbose)
    settings = resolve_settings(cli_db_path=db_path, cli_config=config)
    _console.log(f"audit log: {settings.db_path}")
    _console.log(f"server   : {server}")
    try:
        result = asyncio.run(run_proxy(server, settings=settings))
    except KeyboardInterrupt:
        _console.log("interrupted")
        sys.exit(130)
    except Exception:
        _console.print_exception()
        sys.exit(1)
    if result.events_dropped:
        _console.log(
            f"warning: {result.events_dropped} events were dropped "
            f"due to a full queue — raise queue_max"
        )
    sys.exit(result.exit_code)


@main.command("logs")
@click.option(
    "--tail",
    type=int,
    default=50,
    show_default=True,
    help="Number of recent events to display.",
)
@click.option("--follow", "-f", is_flag=True, help="Stream new events as they arrive.")
@click.option(
    "--db-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override the audit log location.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML config file.",
)
def cmd_logs(
    tail: int,
    follow: bool,
    db_path: Path | None,
    config: Path | None,
) -> None:
    """Inspect the audit log."""
    settings = resolve_settings(cli_db_path=db_path, cli_config=config)
    if not settings.db_path.exists():
        _console.print(
            f"[yellow]no audit log at {settings.db_path}. Run "
            f"`mcp-firewall run --server ...` first.[/yellow]"
        )
        sys.exit(1)
    try:
        if follow:
            asyncio.run(_run_follow(settings, initial_tail=tail))
        else:
            asyncio.run(_run_tail(settings, tail))
    except KeyboardInterrupt:
        sys.exit(130)


async def _run_tail(settings: Settings, tail: int) -> None:
    async with Storage(settings.db_path) as storage:
        rows = await storage.latest_events(limit=tail)
    if not rows:
        _console.print("[dim]no events yet.[/dim]")
        return
    Console().print(_render_table(rows))


async def _run_follow(settings: Settings, *, initial_tail: int) -> None:
    out = Console()
    table = _empty_table()
    rendered = 0
    with Live(table, console=out, refresh_per_second=8, transient=False) as live:
        async with Storage(settings.db_path) as storage:
            async for row in stream_events(storage, initial_tail=initial_tail):
                _add_row(table, row)
                rendered += 1
                live.update(table)


def _setup_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _empty_table() -> Table:
    table = Table(show_lines=False, expand=True)
    table.add_column("id", justify="right", style="dim", no_wrap=True)
    table.add_column("ts", style="dim", no_wrap=True)
    table.add_column("dir", justify="center", no_wrap=True)
    table.add_column("kind", no_wrap=True)
    table.add_column("method", style="cyan", no_wrap=True)
    table.add_column("msg_id", style="dim", no_wrap=True)
    table.add_column("payload", overflow="ellipsis", no_wrap=True)
    return table


def _render_table(rows: list[aiosqlite.Row]) -> Table:
    table = _empty_table()
    for row in rows:
        _add_row(table, row)
    return table


_DIRECTION_ARROW = {
    "client_to_server": Text("→", style="bold blue"),
    "server_to_client": Text("←", style="bold green"),
}

_KIND_STYLE = {
    "request": "blue",
    "response": "green",
    "notification": "yellow",
    "error": "bold red",
    "raw": "dim",
    "parse_error": "bold red",
}


def _add_row(table: Table, row: aiosqlite.Row) -> None:
    table.add_row(
        str(row["id"]),
        _short_ts(row["ts"]),
        _DIRECTION_ARROW.get(row["direction"], Text("?")),
        Text(row["kind"], style=_KIND_STYLE.get(row["kind"], "white")),
        row["method"] or "",
        row["msg_id"] or "",
        _payload_summary(row),
    )


def _short_ts(ts: str) -> str:
    """Trim ISO-8601 to HH:MM:SS.fff for the viewer (the full ts is in the DB)."""
    if "T" not in ts:
        return ts
    after_t = ts.split("T", 1)[1]
    return after_t[:12]


def _payload_summary(row: aiosqlite.Row) -> str:
    for column in ("params_json", "result_json", "error_json"):
        value = row[column]
        if value:
            return _compact(value)
    return _compact(row["raw"])


def _compact(value: str, max_len: int = 120) -> str:
    s = value.strip()
    try:
        decoded: Any = json.loads(s)
        s = json.dumps(decoded, separators=(",", ":"), ensure_ascii=False)
    except json.JSONDecodeError:
        pass
    if len(s) > max_len:
        return s[: max_len - 1] + "…"
    return s


if __name__ == "__main__":  # pragma: no cover
    main()
