"""mcp-firewall — prompt-injection firewall and audit log for MCP servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-firewall")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
