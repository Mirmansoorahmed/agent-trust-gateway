"""Agent-token and downstream-token validation.

The gateway accepts only agent tokens (audience = the gateway). Downstream MCP
servers accept only tokens this gateway minted for that server, plus an optional
lab-only direct token used by the no-gateway baseline.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import ExpiredSignatureError, InvalidTokenError

from gateway.keys import load_public_pem


class AuthError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class AgentIdentity:
    agent_id: str
    scopes: list[str]
    issuer: str
    audience: list[str]
    token: str
    issued_at: int
    expires_at: int
    claims: dict = field(default_factory=dict)

    @property
    def lifetime_seconds(self) -> int:
        return self.expires_at - self.issued_at


def _audiences(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return []


def _scopes(value: object) -> list[str]:
    if isinstance(value, str):
        return [part for part in value.split() if part]
    if isinstance(value, list):
        return [str(part) for part in value if str(part)]
    return []


def authenticate_agent_token(
    token: str,
    *,
    public_keys: list[RSAPublicKey],
    issuer: str,
    audience: str,
    max_ttl_seconds: int = 600,
    now: int | None = None,
) -> AgentIdentity:
    """Validate an agent token. Raises AuthError; never returns a partial identity."""
    if not token or not public_keys:
        raise AuthError("invalid_token", "missing bearer token")
    current = int(time.time() if now is None else now)
    last_error = AuthError("invalid_token", "signature did not match a trusted key")
    payload: dict | None = None
    for key in public_keys:
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=issuer,
                options={
                    "require": ["exp", "iat", "iss"],
                    "verify_aud": False,
                },
                leeway=5,
            )
            break
        except ExpiredSignatureError:
            last_error = AuthError("expired", "token is expired")
        except InvalidTokenError as exc:
            last_error = AuthError("invalid_token", str(exc))
    if payload is None:
        raise last_error

    audiences = _audiences(payload.get("aud"))
    if audience not in audiences:
        raise AuthError("wrong_audience", "token audience is not the gateway")

    issued_at = int(payload["iat"])
    expires_at = int(payload["exp"])
    if expires_at <= current:
        raise AuthError("expired", "token is expired")
    if expires_at - issued_at > max_ttl_seconds:
        raise AuthError("ttl_exceeded", "token lifetime exceeds 10 minutes")

    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise AuthError("missing_agent_id", "agent_id claim is required")

    scopes = _scopes(payload.get("scope") or payload.get("scp"))
    if not scopes:
        raise AuthError("missing_scope", "scope claim is required")

    token_use = payload.get("token_use")
    if token_use not in (None, "agent"):
        raise AuthError("wrong_token_use", "gateway accepts agent tokens only")

    return AgentIdentity(
        agent_id=agent_id,
        scopes=scopes,
        issuer=str(payload["iss"]),
        audience=audiences,
        token=token,
        issued_at=issued_at,
        expires_at=expires_at,
        claims={k: v for k, v in payload.items() if k != "scope"},
    )


@dataclass
class DownstreamClaims:
    issuer: str
    audience: list[str]
    agent_id: str
    scopes: list[str]
    token_use: str
    token_sha256: str


def _sha256(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


def verify_server_token(
    token: str,
    *,
    server_id: str,
    gateway_public_key: RSAPublicKey,
    allow_direct: bool = False,
    direct_public_key: RSAPublicKey | None = None,
    direct_issuer: str = "http://lab-direct.local",
    gateway_issuer: str = "agent-trust-gateway",
    now: int | None = None,
) -> DownstreamClaims:
    """Validate a token presented to an MCP server.

    The agent's own token fails this check because its audience is the gateway
    and its issuer is the IdP, not the gateway.
    """
    if not token:
        raise AuthError("invalid_token", "missing bearer token")
    current = int(time.time() if now is None else now)
    header = jwt.get_unverified_header(token)
    unverified = jwt.decode(token, options={"verify_signature": False})
    token_use = unverified.get("token_use")
    if token_use == "downstream":
        key: RSAPublicKey | None = gateway_public_key
        expected_iss = gateway_issuer
    elif token_use == "direct" and allow_direct:
        key = direct_public_key
        expected_iss = direct_issuer
    else:
        raise AuthError("rejected_token_use", "server rejected this token use")
    if key is None:
        raise AuthError("invalid_token", "no key configured for this token")
    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=expected_iss,
            options={"require": ["exp", "iat", "iss"], "verify_aud": False},
            leeway=5,
        )
    except ExpiredSignatureError as exc:
        raise AuthError("expired", "token is expired") from exc
    except InvalidTokenError as exc:
        raise AuthError("invalid_token", str(exc)) from exc
    audiences = _audiences(payload.get("aud"))
    if server_id not in audiences:
        raise AuthError("wrong_audience", "token audience is not this server")
    if int(payload["exp"]) <= current:
        raise AuthError("expired", "token is expired")
    agent_id = payload.get("agent_id") or payload.get("sub")
    if not isinstance(agent_id, str) or not agent_id:
        raise AuthError("missing_agent_id", "agent_id claim is required")
    # header is checked so a swapped algorithm cannot sneak through PyJWT's default,
    # and so tests can assert the token really is RS256.
    if header.get("alg") != "RS256":
        raise AuthError("invalid_token", "unexpected signing algorithm")
    return DownstreamClaims(
        issuer=str(payload["iss"]),
        audience=audiences,
        agent_id=agent_id,
        scopes=_scopes(payload.get("scope")),
        token_use=str(payload.get("token_use")),
        token_sha256=_sha256(token),
    )


def public_key_from_pem_file(path: str) -> RSAPublicKey:
    return load_public_pem(PathBytes(path))


def PathBytes(path: str) -> bytes:
    from pathlib import Path

    return Path(path).read_bytes()
