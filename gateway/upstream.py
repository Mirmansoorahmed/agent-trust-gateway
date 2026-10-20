"""Upstream MCP calls on one dedicated task.

Streamable HTTP clients bind AnyIO cancel scopes to the task that entered
them. A single worker task owns every client, so the gateway's request tasks
only submit work to that worker.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


@dataclass
class _Holder:
    token: str = ""


class _HolderAuth(httpx2.Auth):
    def __init__(self, holder: _Holder):
        self.holder = holder

    def auth_flow(self, request):
        if self.holder.token:
            request.headers["Authorization"] = f"Bearer {self.holder.token}"
        yield request


@dataclass
class _Job:
    kind: str
    url: str
    token: str
    name: str
    arguments: dict
    future: Future


class UpstreamPool:
    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._queue: asyncio.Queue[_Job | None] | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._thread_main, name="upstream-mcp", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("upstream worker did not start")

    def _thread_main(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._queue = asyncio.Queue()
        self._loop.create_task(self._worker())
        self._ready.set()
        self._loop.run_forever()

    async def _client(self, clients, holders, https, url: str, token: str) -> tuple[Client, _Holder]:
        if url in clients:
            return clients[url], holders[url]
        holder = _Holder(token=token)
        http = httpx2.AsyncClient(auth=_HolderAuth(holder), timeout=httpx2.Timeout(30.0))
        https.append(http)
        client = Client(streamable_http_client(url, http_client=http), mode="legacy")
        await client.__aenter__()
        clients[url] = client
        holders[url] = holder
        return client, holder

    async def _worker(self) -> None:
        assert self._queue is not None
        clients: dict[str, Client] = {}
        holders: dict[str, _Holder] = {}
        https: list[httpx2.AsyncClient] = []
        try:
            while True:
                job = await self._queue.get()
                if job is None:
                    break
                try:
                    client, holder = await self._client(clients, holders, https, job.url, job.token)
                    holder.token = job.token
                    if job.kind == "list":
                        result = await client.list_tools()
                        payload = [
                            {
                                "name": tool.name,
                                "description": tool.description or "",
                                "input_schema": tool.input_schema or {},
                            }
                            for tool in result.tools
                        ]
                    else:
                        result = await client.call_tool(job.name, job.arguments)
                        if not result.content:
                            payload = ""
                        else:
                            first = result.content[0]
                            payload = getattr(first, "text", str(first))
                    job.future.set_result(payload)
                except Exception as exc:
                    if not job.future.done():
                        job.future.set_exception(exc)
        finally:
            for client in clients.values():
                await client.__aexit__(None, None, None)
            for http in https:
                await http.aclose()

    async def _submit(self, job: _Job) -> Any:
        assert self._queue is not None
        self._loop.call_soon_threadsafe(self._queue.put_nowait, job)
        return await asyncio.wrap_future(job.future)

    async def list_tools(self, url: str, token: str) -> list[dict[str, Any]]:
        job = _Job("list", url, token, "", {}, Future())
        return await self._submit(job)

    async def call_tool(self, url: str, token: str, name: str, arguments: dict) -> str:
        job = _Job("call", url, token, name, arguments, Future())
        return await self._submit(job)

    async def aclose(self) -> None:
        if self._queue is not None:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
        self._thread.join(timeout=5)
        self._loop.call_soon_threadsafe(self._loop.stop)
