"""Run one task against a live gateway with the configured model provider.

    ATG_MODEL_PROVIDER=ollama python -m agents.run "List the Nordlicht inbox"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os

from agents.graph import build_graph
from agents.providers import provider_from_env
from eval.lab import Lab


async def _main(task: str) -> None:
    provider = provider_from_env()
    lab = Lab()
    lab.start()
    try:
        from eval.runner import Hub

        hub = Hub()
        token = lab.agent_token("mail-assistant", ["mail.read", "mail.send"])
        url = f"http://127.0.0.1:{lab.gateway_port}/mcp"
        listed = await hub.list_tools(url, token)
        catalogue = [
            {"name": tool["name"], "description": tool["description"], "input_schema": tool.get("inputSchema") or {}}
            for tool in listed
            if tool["name"].startswith("mail.")
        ]

        def call_tool(name: str, arguments: dict) -> dict:
            return asyncio.get_event_loop().run_until_complete(
                hub.call(url, token, name, arguments, session="agent-run")
            )

        # The graph is synchronous. Drive the tool calls on this loop instead.
        async def call_tool_async(name: str, arguments: dict) -> dict:
            body = await hub.call(url, token, name, arguments, session="agent-run")
            return body

        pending: list[tuple[str, dict]] = []

        def call_tool_sync(name: str, arguments: dict) -> dict:
            pending.append((name, arguments))
            return {"queued": name}

        graph = build_graph(provider, call_tool=call_tool_sync, catalogue=catalogue, max_steps=1)
        state = graph.invoke(
            {
                "messages": [{"role": "user", "content": task}],
                "steps": 0,
                "traces": [],
            }
        )
        traces = []
        for name, arguments in pending:
            traces.append({"tool": name, "arguments": arguments, "result": await call_tool_async(name, arguments)})
        print(
            json.dumps(
                {
                    "provider": provider.name,
                    "model": getattr(provider, "model", ""),
                    "assistant": state["messages"][-1],
                    "traces": traces,
                },
                indent=2,
                default=str,
            )
        )
        await hub.aclose()
    finally:
        lab.stop()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("task", nargs="?", default="List the Nordlicht inbox and stop.")
    args = parser.parse_args()
    os.environ.setdefault("ATG_MODEL_PROVIDER", "ollama")
    asyncio.run(_main(args.task))


if __name__ == "__main__":
    main()
