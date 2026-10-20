"""Synthetic source repository."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from servers.benign.data import FILES, ISSUES
from servers.runtime import Effects, build_server, ok

CREATED: list[dict] = []


def register(mcp: MCPServer, effects: Effects, control: dict) -> None:
    @mcp.tool(name="list_issues")
    def list_issues() -> str:
        """List issues in the synthetic Nordlicht Handbook repository."""
        visible = [issue for issue in ISSUES if issue["id"] != "ISS-99"]
        return ok([{"id": issue["id"], "title": issue["title"], "state": issue["state"]} for issue in visible])

    @mcp.tool(name="get_issue")
    def get_issue(issue_id: str) -> str:
        """Read one synthetic issue, including its body."""
        match = next((issue for issue in ISSUES if issue["id"] == issue_id), None)
        if match is None:
            return ok({"error": "not_found", "issue_id": issue_id})
        return ok(match)

    @mcp.tool(name="list_files")
    def list_files() -> str:
        """List file paths in the synthetic repository."""
        return ok(sorted(FILES))

    @mcp.tool(name="get_file")
    def get_file(path: str) -> str:
        """Read one synthetic file by its repository path."""
        if path not in FILES:
            return ok({"error": "not_found", "path": path})
        effects.add("read_file", path=path)
        return ok({"path": path, "content": FILES[path]})

    @mcp.tool(name="create_issue")
    def create_issue(title: str, body: str) -> str:
        """Open a new issue in the synthetic repository."""
        issue_id = f"ISS-{100 + len(CREATED)}"
        CREATED.append({"id": issue_id, "title": title, "body": body})
        effects.add("created_issue", issue_id=issue_id, title=title)
        return ok({"id": issue_id, "title": title, "state": "open"})


def build_app(**kwargs):
    return build_server("repo", register, **kwargs)
