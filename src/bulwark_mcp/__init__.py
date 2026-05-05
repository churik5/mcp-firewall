"""bulwark-mcp — prompt-injection firewall and audit log for MCP servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bulwark-mcp")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
