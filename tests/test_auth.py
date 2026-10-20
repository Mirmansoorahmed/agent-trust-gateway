"""Token validation. These tests do not start servers."""

import time

import pytest

from gateway.auth import AuthError, authenticate_agent_token, verify_server_token
from gateway.keys import SigningKey
from gateway.tokens import AGENT_ISSUER, DIRECT_ISSUER, DownstreamMinter, LabIssuer, TokenMinter


@pytest.fixture
def keys():
    lab = SigningKey.generate("lab")
    gateway = SigningKey.generate("gateway")
    return lab, gateway


def test_agent_token_round_trip(keys):
    lab, _gateway = keys
    token = LabIssuer(lab).agent_token(agent_id="mail-assistant", scopes=["mail.read", "mail.send"])
    identity = authenticate_agent_token(
        token,
        public_keys=[lab.public_key],
        issuer=AGENT_ISSUER,
        audience="agent-trust-gateway",
    )
    assert identity.agent_id == "mail-assistant"
    assert identity.scopes == ["mail.read", "mail.send"]
    assert identity.lifetime_seconds <= 600


def test_expired_token_is_rejected(keys):
    lab, _gateway = keys
    token = LabIssuer(lab).agent_token(
        agent_id="mail-assistant",
        scopes=["mail.read"],
        now=int(time.time()) - 1000,
        ttl_seconds=300,
    )
    with pytest.raises(AuthError) as caught:
        authenticate_agent_token(
            token,
            public_keys=[lab.public_key],
            issuer=AGENT_ISSUER,
            audience="agent-trust-gateway",
        )
    assert caught.value.code == "expired"


def test_wrong_audience_is_rejected(keys):
    lab, _gateway = keys
    token = LabIssuer(lab).agent_token(agent_id="mail-assistant", scopes=["mail.read"], audience="elsewhere")
    with pytest.raises(AuthError) as caught:
        authenticate_agent_token(
            token,
            public_keys=[lab.public_key],
            issuer=AGENT_ISSUER,
            audience="agent-trust-gateway",
        )
    assert caught.value.code == "wrong_audience"


def test_long_ttl_is_rejected(keys):
    lab, _gateway = keys
    token = LabIssuer(lab).agent_token(agent_id="mail-assistant", scopes=["mail.read"], ttl_seconds=3600)
    with pytest.raises(AuthError) as caught:
        authenticate_agent_token(
            token,
            public_keys=[lab.public_key],
            issuer=AGENT_ISSUER,
            audience="agent-trust-gateway",
        )
    assert caught.value.code == "ttl_exceeded"


def test_wrong_issuer_is_rejected(keys):
    lab, _gateway = keys
    token = TokenMinter(lab, "http://evil.example").mint(
        subject="mail-assistant",
        audience="agent-trust-gateway",
        scopes=["mail.read"],
        token_use="agent",
        ttl_seconds=120,
    )
    with pytest.raises(AuthError):
        authenticate_agent_token(
            token,
            public_keys=[lab.public_key],
            issuer=AGENT_ISSUER,
            audience="agent-trust-gateway",
        )


def test_downstream_token_is_not_an_agent_token(keys):
    lab, gateway = keys
    token = DownstreamMinter(gateway).for_server(agent_id="mail-assistant", server_id="mail", scopes=["mail.read"])
    with pytest.raises(AuthError):
        authenticate_agent_token(
            token,
            public_keys=[gateway.public_key],
            issuer="agent-trust-gateway",
            audience="agent-trust-gateway",
        )


def test_server_rejects_the_agent_token(keys):
    lab, gateway = keys
    token = LabIssuer(lab).agent_token(agent_id="mail-assistant", scopes=["mail.read"])
    with pytest.raises(AuthError) as caught:
        verify_server_token(
            token,
            server_id="mail",
            gateway_public_key=gateway.public_key,
            allow_direct=True,
            direct_public_key=lab.public_key,
        )
    assert caught.value.code == "rejected_token_use"


def test_server_accepts_matching_downstream_token(keys):
    _lab, gateway = keys
    minter = DownstreamMinter(gateway)
    token = minter.for_server(agent_id="mail-assistant", server_id="mail", scopes=["mail.read"])
    claims = verify_server_token(token, server_id="mail", gateway_public_key=gateway.public_key)
    assert claims.token_use == "downstream"
    assert claims.audience == ["mail"]
    assert claims.token_sha256 != ""


def test_server_rejects_downstream_token_for_another_server(keys):
    _lab, gateway = keys
    token = DownstreamMinter(gateway).for_server(
        agent_id="mail-assistant", server_id="mail", scopes=["mail.read"]
    )
    with pytest.raises(AuthError) as caught:
        verify_server_token(token, server_id="repo", gateway_public_key=gateway.public_key)
    assert caught.value.code == "wrong_audience"


def test_direct_token_is_accepted_only_when_enabled(keys):
    lab, gateway = keys
    token = LabIssuer(lab).direct_token(agent_id="mail-assistant", server_id="mail", scopes=["mail.read"])
    with pytest.raises(AuthError):
        verify_server_token(token, server_id="mail", gateway_public_key=gateway.public_key, allow_direct=False)
    claims = verify_server_token(
        token,
        server_id="mail",
        gateway_public_key=gateway.public_key,
        allow_direct=True,
        direct_public_key=lab.public_key,
        direct_issuer=DIRECT_ISSUER,
    )
    assert claims.token_use == "direct"


def test_agent_and_downstream_tokens_differ(keys):
    lab, gateway = keys
    agent = LabIssuer(lab).agent_token(agent_id="mail-assistant", scopes=["mail.read"])
    downstream = DownstreamMinter(gateway).for_server(
        agent_id="mail-assistant", server_id="mail", scopes=["mail.read"]
    )
    assert agent != downstream
