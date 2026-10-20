"""Mint a mock-OIDC token and call the gateway. Run this on the compose network.

    docker compose exec gateway python /app/scripts/quickstart.py
"""

from __future__ import annotations

import asyncio
import os

import httpx

from eval.lab import mcp_call


async def main() -> None:
    issuer = os.environ.get("ATG_OIDC_ISSUER", "http://mock-oidc:8080/agents")
    gateway = os.environ.get("ATG_GATEWAY_URL", "http://127.0.0.1:8080/mcp")
    # The mock issuer accepts any client secret. It is not a production credential.
    form = {
        "grant_type": "client_credentials",
        "client_id": "mail-assistant",
        "client_secret": "lab",
        "scope": "mail.read mail.send",
        "audience": "agent-trust-gateway",
    }
    response = httpx.post(f"{issuer}/token", data=form, timeout=10)
    response.raise_for_status()
    token = response.json()["access_token"]
    body = await mcp_call(gateway, token, "mail.list_inbox", {})
    decision = body.get("atg_decision")
    print({"atg_decision": decision, "reason": body.get("reason"), "token_use": (body.get("token") or {}).get("use")})
    if decision != "allow":
        raise SystemExit(f"quickstart expected allow, got {decision}: {body.get('reason')}")


if __name__ == "__main__":
    asyncio.run(main())
