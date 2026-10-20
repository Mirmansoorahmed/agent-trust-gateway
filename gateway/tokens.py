"""Mint short-lived audience-scoped tokens. The agent token is never copied."""

from __future__ import annotations

import time
import uuid

import jwt

from gateway.keys import SigningKey

GATEWAY_ISSUER = "agent-trust-gateway"
DIRECT_ISSUER = "http://lab-direct.local"
AGENT_ISSUER = "http://lab-issuer.local"


class TokenMinter:
    def __init__(self, signing_key: SigningKey, issuer: str):
        self.signing_key = signing_key
        self.issuer = issuer

    def mint(
        self,
        *,
        subject: str,
        audience: str,
        scopes: list[str],
        token_use: str,
        ttl_seconds: int,
        extra: dict | None = None,
        now: int | None = None,
    ) -> str:
        issued_at = int(time.time() if now is None else now)
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": issued_at,
            "exp": issued_at + ttl_seconds,
            "jti": str(uuid.uuid4()),
            "agent_id": subject,
            "scope": " ".join(scopes),
            "token_use": token_use,
            "kid": self.signing_key.kid,
        }
        if extra:
            payload.update(extra)
        return jwt.encode(
            payload,
            self.signing_key.private_key,
            algorithm="RS256",
            headers={"kid": self.signing_key.kid},
        )


class DownstreamMinter(TokenMinter):
    def __init__(self, signing_key: SigningKey, ttl_seconds: int = 60):
        super().__init__(signing_key, GATEWAY_ISSUER)
        self.ttl_seconds = ttl_seconds

    def for_server(self, *, agent_id: str, server_id: str, scopes: list[str]) -> str:
        return self.mint(
            subject=agent_id,
            audience=server_id,
            scopes=scopes,
            token_use="downstream",
            ttl_seconds=self.ttl_seconds,
        )


class LabIssuer(TokenMinter):
    """Local stand-in for the mock OIDC issuer. Compose uses navikt instead."""

    def __init__(self, signing_key: SigningKey):
        super().__init__(signing_key, AGENT_ISSUER)

    def agent_token(
        self,
        *,
        agent_id: str,
        scopes: list[str],
        audience: str = "agent-trust-gateway",
        ttl_seconds: int = 300,
        now: int | None = None,
        extra: dict | None = None,
    ) -> str:
        return self.mint(
            subject=agent_id,
            audience=audience,
            scopes=scopes,
            token_use="agent",
            ttl_seconds=ttl_seconds,
            extra=extra,
            now=now,
        )

    def direct_token(
        self,
        *,
        agent_id: str,
        server_id: str,
        scopes: list[str],
        ttl_seconds: int = 300,
    ) -> str:
        # Direct tokens use a different issuer so they cannot be confused with
        # IdP agent tokens. The minter issuer is swapped for this one call.
        saved = self.issuer
        self.issuer = DIRECT_ISSUER
        try:
            return self.mint(
                subject=agent_id,
                audience=server_id,
                scopes=scopes,
                token_use="direct",
                ttl_seconds=ttl_seconds,
            )
        finally:
            self.issuer = saved
