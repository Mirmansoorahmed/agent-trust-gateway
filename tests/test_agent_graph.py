"""The LangGraph loop with a scripted provider. No model server required."""

from agents.graph import build_graph
from agents.providers import ModelTurn, ScriptedProvider, ToolCall, parse_ollama_message


def test_parse_ollama_tool_call():
    turn = parse_ollama_message(
        {
            "content": "",
            "tool_calls": [{"function": {"name": "mail.list_inbox", "arguments": {}}}],
        }
    )
    assert turn.tool_calls[0].name == "mail.list_inbox"


def test_graph_calls_the_tool_once():
    provider = ScriptedProvider(
        [
            ModelTurn(text="", tool_calls=[ToolCall("mail.list_inbox", {})]),
            ModelTurn(text="Two messages are waiting."),
        ]
    )
    seen = []

    def call_tool(name, arguments):
        seen.append((name, arguments))
        return {"atg_decision": "allow", "output": "inbox"}

    graph = build_graph(
        provider,
        call_tool=call_tool,
        catalogue=[{"name": "mail.list_inbox", "description": "List mail", "input_schema": {"type": "object"}}],
    )
    state = graph.invoke({"messages": [{"role": "user", "content": "List my inbox"}], "steps": 0, "traces": []})
    assert seen == [("mail.list_inbox", {})]
    assert state["traces"][0]["result"]["atg_decision"] == "allow"
    assert state["messages"][-1]["content"] == "Two messages are waiting."
