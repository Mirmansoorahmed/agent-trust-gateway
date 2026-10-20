"""OPA decision client. If OPA cannot be reached the call is denied."""

from __future__ import annotations

from typing import Protocol

import httpx


class PolicyClient(Protocol):
    async def decide(self, payload: dict) -> dict: ...


class OpaClient:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def decide(self, payload: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/v1/data/atg/authz",
                    json={"input": payload},
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            return {
                "decision": "deny",
                "reason": f"opa unavailable: {exc.__class__.__name__}",
                "reasons": ["opa unavailable"],
                "approval_reasons": [],
                "error": str(exc),
            }
        result = response.json().get("result") or {}
        if "decision" not in result:
            return {
                "decision": "deny",
                "reason": "opa returned no decision",
                "reasons": ["opa empty"],
                "approval_reasons": [],
            }
        result.setdefault("reasons", [])
        result.setdefault("approval_reasons", [])
        return result

    async def aclose(self) -> None:
        return None
