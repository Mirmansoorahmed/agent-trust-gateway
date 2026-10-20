"""FastAPI application: MCP endpoint, JWKS, approval API, health."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import mcp_types as types
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.lowlevel.server import Server
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from gateway.auth import AgentIdentity
from gateway.config import Settings
from gateway.service import GatewayService
from gateway.tokens import DownstreamMinter
from gateway.ui import approvals_page
from gateway.verifiers import AgentTokenVerifier


def _identity(access: AccessToken) -> AgentIdentity:
    claims = access.claims or {}
    return AgentIdentity(
        agent_id=access.subject or access.client_id,
        scopes=list(access.scopes),
        issuer=str(claims.get("iss", "")),
        audience=["agent-trust-gateway"],
        token=access.token,
        issued_at=0,
        expires_at=int(access.expires_at or 0),
    )


def _session_id(ctx) -> str:
    request = getattr(ctx, "request", None)
    headers = getattr(request, "headers", None)
    if headers is not None:
        return headers.get("x-atg-session") or headers.get("mcp-session-id") or "default"
    return "default"


def create_app(
    settings: Settings,
    *,
    agent_public_keys: list[RSAPublicKey],
    minter: DownstreamMinter,
) -> FastAPI:
    service = GatewayService(settings, minter=minter)
    verifier = AgentTokenVerifier(
        public_keys=agent_public_keys,
        issuer=settings.oidc_issuer,
        audience=settings.gateway_audience,
        max_ttl_seconds=settings.max_token_ttl_seconds,
    )

    async def on_list_tools(ctx, params):
        access = get_access_token()
        if access is None:
            raise RuntimeError("unauthenticated list")
        tools = await service.list_tools(_identity(access))
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=tool["name"],
                    description=tool["description"],
                    input_schema=tool["input_schema"],
                    meta=tool.get("meta"),
                )
                for tool in tools
            ]
        )

    async def on_call_tool(ctx, params):
        access = get_access_token()
        if access is None:
            raise RuntimeError("unauthenticated call")
        trace = await service.call_tool(
            _identity(access),
            _session_id(ctx),
            params.name,
            params.arguments or {},
        )
        body = {
            "atg_decision": trace.decision,
            "reason": trace.reason,
            "reasons": trace.reasons,
            "approval_reasons": trace.approval_reasons,
            "approval_id": trace.approval_id,
            "manifest_sha256": trace.manifest_hash,
            "drift": trace.drift,
            "poison_flags": trace.poison_flags,
            "labels": trace.labels,
            "output_flags": trace.output_flags,
            "overhead_ms": round(trace.overhead_ms, 3),
            "upstream_ms": round(trace.upstream_ms, 3),
            "output": trace.text,
            "token": trace.token_observation,
            "agent_token_sha256": trace.agent_token_sha256,
        }
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(body))],
            structured_content=body,
            is_error=trace.decision != "allow",
            meta={"atg.decision": trace.decision},
        )

    low = Server(
        "agent-trust-gateway",
        version="0.1.0",
        instructions="Tools are namespaced as server.tool. Every call is authorized by OPA.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    mcp_app = low.streamable_http_app(
        json_response=True,
        stateless_http=True,
        host="0.0.0.0",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(settings.auth_issuer_url),
            resource_server_url=AnyHttpUrl(settings.resource_server_url),
            validate_token_resource=False,
        ),
        token_verifier=verifier,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with mcp_app.router.lifespan_context(mcp_app):
            yield
            await service.aclose()

    app = FastAPI(title="Agent Trust Gateway", version="0.1.0", lifespan=lifespan)
    app.state.service = service
    app.state.settings = settings

    def require_approver(token: str | None) -> None:
        if token != settings.approver_token:
            raise HTTPException(status_code=401, detail="approver token required")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "agent-trust-gateway"}

    @app.get("/jwks")
    @app.get("/.well-known/jwks.json")
    async def jwks() -> dict:
        return minter.signing_key.jwks()

    @app.get("/approvals", response_class=HTMLResponse)
    async def approvals_ui() -> str:
        return approvals_page()

    @app.get("/api/approvals")
    async def list_approvals(x_approver_token: str | None = Header(default=None)) -> list[dict]:
        require_approver(x_approver_token)
        return [item.__dict__ for item in service.approvals.list()]

    @app.post("/api/approvals/{approval_id}")
    async def decide_approval(
        approval_id: str,
        request: Request,
        x_approver_token: str | None = Header(default=None),
    ) -> dict:
        require_approver(x_approver_token)
        body = await request.json()
        decision = body.get("decision")
        if decision not in {"approved", "denied"}:
            raise HTTPException(status_code=400, detail="decision must be approved or denied")
        try:
            item = service.approvals.decide(
                approval_id,
                decision,
                actor=body.get("actor", "approver"),
                note=body.get("note", ""),
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown approval") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return item.__dict__

    @app.get("/api/alerts")
    async def alerts(x_approver_token: str | None = Header(default=None)) -> list[dict]:
        require_approver(x_approver_token)
        return list(service.manifests.alerts)

    @app.post("/admin/reset")
    async def reset(x_approver_token: str | None = Header(default=None)) -> dict:
        require_approver(x_approver_token)
        service.sessions.reset()
        service.manifests.reset()
        service.approvals.reset()
        return {"reset": True}

    # Mount last so the routes above keep priority over the MCP app's catch-all.
    app.mount("/", mcp_app)
    return app


def json_error(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)
