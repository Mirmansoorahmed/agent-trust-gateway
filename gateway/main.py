"""Process entrypoint used by Docker and `uvicorn gateway.main:app`."""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx

from gateway.app import create_app
from gateway.config import load_settings
from gateway.keys import SigningKey, load_public_pem
from gateway.tokens import DownstreamMinter

_KEY_PATH = Path(os.environ.get("ATG_SIGNING_KEY", "data/gateway_signing.pem"))
_AGENT_PEM = os.environ.get("ATG_AGENT_PUBLIC_KEY_FILE")


def _agent_keys(settings):
    if _AGENT_PEM:
        return [load_public_pem(Path(_AGENT_PEM).read_bytes())]
    if settings.oidc_jwks_url:
        last: Exception | None = None
        for _ in range(30):
            try:
                response = httpx.get(settings.oidc_jwks_url, timeout=5)
                response.raise_for_status()
                keys = []
                for jwk in response.json().get("keys", []):
                    import jwt

                    keys.append(jwt.PyJWK.from_dict(jwk).key)
                if keys:
                    return keys
                last = RuntimeError(f"no keys at {settings.oidc_jwks_url}")
            except Exception as exc:
                last = exc
            time.sleep(1)
        raise RuntimeError(f"could not load JWKS from {settings.oidc_jwks_url}") from last
    raise RuntimeError("set ATG_AGENT_PUBLIC_KEY_FILE or ATG_OIDC_JWKS_URL")


def build_app():
    settings = load_settings()
    signing = SigningKey.load_or_create(_KEY_PATH, kid="gateway-1")
    public_path = Path(os.environ.get("ATG_SIGNING_PUBLIC_FILE", "data/gateway_public.pem"))
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(signing.public_pem())
    return create_app(
        settings,
        agent_public_keys=_agent_keys(settings),
        minter=DownstreamMinter(signing, ttl_seconds=settings.downstream_ttl_seconds),
    )


app = build_app()
