"""data_breach_detector — read-only breach-intelligence MCP server."""

from ._version import SERVER_VERSION
from .server import mcp

__version__ = SERVER_VERSION
__all__ = ["mcp"]
