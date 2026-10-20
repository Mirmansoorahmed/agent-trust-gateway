"""One MCP client per upstream URL, owned by the runner task."""

from __future__ import annotations

import json
import time

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


class _HolderAuth(httpx2.Auth):
    def __init__(self, holder: dict):
        self.holder = holder

    def auth_flow(self, request):
        token = self.holder.get("token") or ""
        if token:
            request.headers["Authorization"] = f"Bearer {token}"
        session = self.holder.get("session") or ""
        if session:
            request.headers["X-ATG-Session"] = session
        yield request


class Hub:
    def __init__(self) -> None:
        self._pool: dict[str, tuple[Client, dict, httpx2.AsyncClient, bool]] = {}

    async def _ensure(self, url: str, token: str, session: str) -> Client:
        if url not in self._pool:
            holder = {"token": token, "session": session}
            http = httpx2.AsyncClient(auth=_HolderAuth(holder), timeout=httpx2.Timeout(60.0))
            client = Client(streamable_http_client(url, http_client=http), mode="legacy")
            self._pool[url] = (client, holder, http, False)
        client, holder, http, entered = self._pool[url]
        holder["token"] = token
        holder["session"] = session
        if not entered:
            await client.__aenter__()
            self._pool[url] = (client, holder, http, True)
        return client

    async def call(self, url: str, token: str, name: str, arguments: dict, session: str = "") -> dict:
        started = time.perf_counter()
        client = await self._ensure(url, token, session)
        try:
            result = await client.call_tool(name, arguments)
        except Exception:
            await self._drop(url)
            raise
        text = ""
        if result.content:
            text = getattr(result.content[0], "text", str(result.content[0]))
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            body = {"raw": text}
        if not isinstance(body, dict):
            body = {"raw": body}
        body["_is_error"] = bool(result.is_error)
        body["_wall_ms"] = (time.perf_counter() - started) * 1000
        return body

    async def list_tools(self, url: str, token: str) -> list[dict]:
        client = await self._ensure(url, token, "")
        result = await client.list_tools()
        tools = []
        for tool in result.tools:
            schema = tool.input_schema or {}
            tools.append(
                {
                    "name": tool.name,
                    "description": tool.description or "",
                    "inputSchema": schema,
                    "input_schema": schema,
                }
            )
        return tools

    async def _drop(self, url: str) -> None:
        entry = self._pool.pop(url, None)
        if entry is None:
            return
        client, _holder, http, entered = entry
        if entered:
            try:
                await client.__aexit__(None, None, None)
            except Exception:
                pass
        try:
            await http.aclose()
        except Exception:
            pass

    async def aclose(self) -> None:
        for client, _holder, http, entered in self._pool.values():
            if entered:
                try:
                    await client.__aexit__(None, None, None)
                except Exception:
                    pass
            try:
                await http.aclose()
            except Exception:
                pass
        self._pool.clear()
