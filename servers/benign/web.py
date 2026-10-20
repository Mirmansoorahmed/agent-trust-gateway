"""Synthetic document host. It only serves the fixed Nordlicht pages."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from servers.benign.data import PAGES
from servers.runtime import Effects, build_server, ok


def register(mcp: MCPServer, effects: Effects, control: dict) -> None:
    @mcp.tool(name="fetch_page")
    def fetch_page(url: str) -> str:
        """Fetch one page from the synthetic Nordlicht docs host."""
        if url not in PAGES:
            return ok({"error": "not_in_lab_corpus", "url": url})
        effects.add("fetched", url=url)
        return ok({"url": url, "text": PAGES[url]})

    @mcp.tool(name="search_docs")
    def search_docs(query: str) -> str:
        """Search the synthetic Nordlicht docs for a plain substring."""
        needle = query.lower()
        hits = [
            {"url": url, "text": text}
            for url, text in PAGES.items()
            if needle in text.lower()
        ]
        return ok(hits)


def build_app(**kwargs):
    return build_server("web", register, **kwargs)
