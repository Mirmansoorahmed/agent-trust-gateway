"""Build an MCP server that requires a gateway-minted token (or a lab direct token)."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse

from gateway.keys import load_public_pem
from gateway.verifiers import ServerTokenVerifier


class Effects:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def add(self, kind: str, **detail: object) -> None:
        self.events.append({"kind": kind, "at": time.time(), **detail})

    def of(self, kind: str) -> list[dict]:
        return [event for event in self.events if event["kind"] == kind]

    def reset(self) -> None:
        self.events.clear()


def token_view() -> dict:
    from mcp.server.auth.middleware.auth_context import get_access_token

    access = get_access_token()
    if access is None:
        return {}
    claims = access.claims or {}
    return {
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "use": claims.get("token_use"),
        "sha256": claims.get("sha256"),
        "scope": " ".join(access.scopes),
        "agent_id": access.subject,
    }


def ok(data: object) -> str:
    return json.dumps({"ok": True, "data": data, "token": token_view()}, default=str)


def load_verifier(server_id: str) -> ServerTokenVerifier:
    gateway_pem = Path(os.environ["ATG_GATEWAY_PUBLIC_KEY_FILE"]).read_bytes()
    direct_pem_path = os.environ.get("ATG_DIRECT_PUBLIC_KEY_FILE")
    direct_key = load_public_pem(Path(direct_pem_path).read_bytes()) if direct_pem_path else None
    return ServerTokenVerifier(
        server_id=server_id,
        gateway_public_key=load_public_pem(gateway_pem),
        allow_direct=os.environ.get("ATG_ALLOW_DIRECT", "1") == "1",
        direct_public_key=direct_key,
    )


def build_server(
    server_id: str,
    register: Callable[[MCPServer, Effects, dict], None],
    *,
    verifier: ServerTokenVerifier | None = None,
    host: str = "0.0.0.0",
) -> object:
    effects = Effects()
    control: dict = {"flipped_at": None}
    verifier = verifier or load_verifier(server_id)
    mcp = MCPServer(
        server_id,
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("http://agent-trust-gateway.local"),
            resource_server_url=AnyHttpUrl(f"http://{server_id}.local/mcp"),
            validate_token_resource=False,
        ),
    )

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": server_id})

    @mcp.custom_route("/admin/effects", methods=["GET"])
    async def get_effects(_: Request) -> JSONResponse:
        return JSONResponse({"events": effects.events})

    @mcp.custom_route("/admin/reset", methods=["POST"])
    async def reset(_: Request) -> JSONResponse:
        effects.reset()
        return JSONResponse({"reset": True})

    @mcp.custom_route("/admin/flip", methods=["POST"])
    async def flip(request: Request) -> JSONResponse:
        mode = request.query_params.get("mode", "description")
        action = control.get("flip")
        if action is None:
            return JSONResponse({"error": "this server does not rug-pull"}, status_code=404)
        flipped_at = time.time()
        action(mode)
        if mode == "reset":
            control["flipped_at"] = None
        else:
            control["flipped_at"] = flipped_at
        return JSONResponse({"flipped": mode != "reset", "mode": mode, "at": flipped_at})

    register(mcp, effects, control)
    app = mcp.streamable_http_app(
        json_response=True,
        stateless_http=True,
        host=host,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    app.state.effects = effects
    app.state.control = control
    return app
