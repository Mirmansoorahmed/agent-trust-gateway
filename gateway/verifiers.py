"""MCP SDK TokenVerifier adapters. The SDK calls these on every HTTP request."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from mcp.server.auth.provider import AccessToken

from gateway.auth import AuthError, authenticate_agent_token, verify_server_token


class AgentTokenVerifier:
    def __init__(
        self,
        *,
        public_keys: list[RSAPublicKey],
        issuer: str,
        audience: str,
        max_ttl_seconds: int,
    ):
        self.public_keys = public_keys
        self.issuer = issuer
        self.audience = audience
        self.max_ttl_seconds = max_ttl_seconds

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            identity = authenticate_agent_token(
                token,
                public_keys=self.public_keys,
                issuer=self.issuer,
                audience=self.audience,
                max_ttl_seconds=self.max_ttl_seconds,
            )
        except AuthError:
            return None
        return AccessToken(
            token=token,
            client_id=identity.agent_id,
            scopes=identity.scopes,
            expires_at=identity.expires_at,
            subject=identity.agent_id,
            claims={"iss": identity.issuer, "agent_id": identity.agent_id},
        )


class ServerTokenVerifier:
    def __init__(
        self,
        *,
        server_id: str,
        gateway_public_key: RSAPublicKey,
        allow_direct: bool,
        direct_public_key: RSAPublicKey | None,
    ):
        self.server_id = server_id
        self.gateway_public_key = gateway_public_key
        self.allow_direct = allow_direct
        self.direct_public_key = direct_public_key

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = verify_server_token(
                token,
                server_id=self.server_id,
                gateway_public_key=self.gateway_public_key,
                allow_direct=self.allow_direct,
                direct_public_key=self.direct_public_key,
            )
        except AuthError:
            return None
        return AccessToken(
            token=token,
            client_id=claims.agent_id,
            scopes=claims.scopes,
            expires_at=None,
            subject=claims.agent_id,
            claims={
                "iss": claims.issuer,
                "aud": claims.audience,
                "token_use": claims.token_use,
                "sha256": claims.token_sha256,
            },
        )
