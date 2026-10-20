"""RSA key management for the lab issuer and the gateway's downstream signer."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def generate_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def dump_private_pem(key: RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def load_private_pem(pem: bytes) -> RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("expected an RSA private key")
    return key


def load_public_pem(pem: bytes) -> RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("expected an RSA public key")
    return key


def public_pem(key: RSAPrivateKey | RSAPublicKey) -> bytes:
    public = key.public_key() if isinstance(key, RSAPrivateKey) else key
    return public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass
class SigningKey:
    kid: str
    private_key: RSAPrivateKey

    @classmethod
    def generate(cls, kid: str) -> SigningKey:
        return cls(kid=kid, private_key=generate_private_key())

    @classmethod
    def load_or_create(cls, path: Path, kid: str) -> SigningKey:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            return cls(kid=kid, private_key=load_private_pem(path.read_bytes()))
        key = cls.generate(kid)
        path.write_bytes(dump_private_pem(key.private_key))
        return key

    @property
    def public_key(self) -> RSAPublicKey:
        return self.private_key.public_key()

    def jwk(self) -> dict:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.public_key))
        jwk["kid"] = self.kid
        jwk["use"] = "sig"
        jwk["alg"] = "RS256"
        return jwk

    def jwks(self) -> dict:
        return {"keys": [self.jwk()]}

    def public_pem(self) -> bytes:
        return public_pem(self.private_key)
