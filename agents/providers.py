"""Model providers. Ollama is the default and needs no API key.

Claude and Gemini adapters run only when their packages and keys are present.
Nothing in the lab requires a paid provider.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ToolCall:
    name: str
    arguments: dict


@dataclass
class ModelTurn:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    provider: str = ""
    model: str = ""


class ModelProvider(Protocol):
    name: str

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn: ...


class ScriptedProvider:
    """Deterministic stand-in used by tests and the controlled experiment."""

    name = "scripted"

    def __init__(self, turns: list[ModelTurn]):
        self._turns = list(turns)
        self.model = "scripted"

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        if not self._turns:
            return ModelTurn(text="done", provider=self.name, model=self.model)
        turn = self._turns.pop(0)
        turn.provider = self.name
        turn.model = self.model
        return turn


def parse_ollama_message(message: dict) -> ModelTurn:
    calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        arguments = function.get("arguments") or {}
        if isinstance(arguments, str):
            import json

            arguments = json.loads(arguments)
        calls.append(ToolCall(name=function.get("name", ""), arguments=arguments))
    return ModelTurn(text=message.get("content") or "", tool_calls=calls, provider="ollama")


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str | None = None, base_url: str | None = None):
        self.model = model or os.environ.get("ATG_OLLAMA_MODEL", "qwen2.5:1.5b")
        self.base_url = (base_url or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip("/")

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        import httpx

        payload = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        response = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=120)
        response.raise_for_status()
        turn = parse_ollama_message(response.json().get("message") or {})
        turn.model = self.model
        return turn


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("ATG_ANTHROPIC_MODEL", "claude-sonnet-4-5")
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        from anthropic import Anthropic

        anthropic_tools = [
            {
                "name": tool["function"]["name"],
                "description": tool["function"].get("description", ""),
                "input_schema": tool["function"].get("parameters") or {"type": "object", "properties": {}},
            }
            for tool in tools
        ]
        converted = []
        for message in messages:
            role = message.get("role", "user")
            if role == "tool":
                converted.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": message.get("tool_call_id", "tool"),
                                "content": message.get("content", ""),
                            }
                        ],
                    }
                )
            else:
                role_name = role if role in {"user", "assistant"} else "user"
                converted.append({"role": role_name, "content": message.get("content", "")})
        kwargs = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": converted or [{"role": "user", "content": "hello"}],
        }
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools
        message = Anthropic().messages.create(**kwargs)
        calls = []
        texts = []
        for block in message.content:
            if block.type == "text":
                texts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(name=block.name, arguments=dict(block.input)))
        return ModelTurn(text="\n".join(texts), tool_calls=calls, provider=self.name, model=self.model)


class GeminiProvider:
    name = "gemini"

    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("ATG_GEMINI_MODEL", "gemini-2.0-flash")
        if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
            raise RuntimeError("GEMINI_API_KEY or GOOGLE_API_KEY is not set")

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelTurn:
        from google import genai
        from google.genai import types

        declarations = [
            types.FunctionDeclaration(
                name=tool["function"]["name"],
                description=tool["function"].get("description", ""),
                parameters=tool["function"].get("parameters") or {"type": "object", "properties": {}},
            )
            for tool in tools
        ]
        contents = [message.get("content", "") for message in messages if message.get("role") != "system"]
        config = None
        if declarations:
            config = types.GenerateContentConfig(tools=[types.Tool(function_declarations=declarations)])
        client = genai.Client()
        response = client.models.generate_content(model=self.model, contents=contents, config=config)
        calls = []
        for candidate in getattr(response, "candidates", None) or []:
            content = getattr(candidate, "content", None)
            for part in getattr(content, "parts", None) or []:
                function_call = getattr(part, "function_call", None)
                if function_call is not None and getattr(function_call, "name", None):
                    arguments = dict(getattr(function_call, "args", None) or {})
                    calls.append(ToolCall(name=function_call.name, arguments=arguments))
        return ModelTurn(
            text=getattr(response, "text", "") or "",
            tool_calls=calls,
            provider=self.name,
            model=self.model,
        )


def provider_from_env() -> ModelProvider:
    """Select a provider from ATG_MODEL_PROVIDER. Default is Ollama."""
    choice = os.environ.get("ATG_MODEL_PROVIDER", "ollama").strip().lower()
    if choice in {"ollama", "local"}:
        return OllamaProvider()
    if choice in {"anthropic", "claude"}:
        return AnthropicProvider()
    if choice in {"gemini", "google"}:
        return GeminiProvider()
    raise RuntimeError(f"unknown ATG_MODEL_PROVIDER {choice}")
