"""A small LangGraph loop: the model asks for a tool, the gateway executes it."""

from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from agents.providers import ModelProvider, ModelTurn


class AgentState(TypedDict):
    messages: list[dict]
    steps: int
    traces: list[dict]


def openai_tools(catalogue: list[dict]) -> list[dict]:
    tools = []
    for tool in catalogue:
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description") or "",
                    "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
                },
            }
        )
    return tools


def build_graph(provider: ModelProvider, *, call_tool, catalogue: list[dict], max_steps: int = 4):
    """`call_tool(name, arguments) -> dict` is the gateway (or a fake in tests)."""

    tools = openai_tools(catalogue)

    def model_node(state: AgentState) -> dict:
        turn: ModelTurn = provider.complete(state["messages"], tools)
        message = {
            "role": "assistant",
            "content": turn.text,
            "tool_calls": [{"name": call.name, "arguments": call.arguments} for call in turn.tool_calls],
        }
        return {"messages": [*state["messages"], message], "steps": state["steps"] + 1}

    def tool_node(state: AgentState) -> dict:
        last = state["messages"][-1]
        traces = list(state["traces"])
        messages = list(state["messages"])
        for call in last.get("tool_calls") or []:
            result = call_tool(call["name"], call.get("arguments") or {})
            traces.append({"tool": call["name"], "arguments": call.get("arguments") or {}, "result": result})
            messages.append(
                {
                    "role": "tool",
                    "name": call["name"],
                    "content": str(result),
                }
            )
        return {"messages": messages, "traces": traces}

    def route(state: AgentState) -> str:
        last = state["messages"][-1]
        if state["steps"] >= max_steps:
            return "end"
        if last.get("tool_calls"):
            return "tools"
        return "end"

    graph = StateGraph(AgentState)
    graph.add_node("model", model_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", route, {"tools": "tools", "end": END})
    graph.add_edge("tools", "model")
    return graph.compile()
