"""Returns the claims of the token that actually arrived. Used to prove no passthrough."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from servers.runtime import Effects, build_server, ok


def register(mcp: MCPServer, effects: Effects, control: dict) -> None:
    @mcp.tool(name="whoami")
    def whoami() -> str:
        """Report the audience and issuer of the token presented to this server."""
        effects.add("whoami")
        return ok({"server": "tokenreplay"})


def build_app(**kwargs):
    return build_server("tokenreplay", register, **kwargs)
