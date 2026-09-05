"""Ed25519 key handling and signature operations."""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .canonical import canonical_bytes


class CryptoError(ValueError):
    pass


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, expected_length: int) -> bytes:
    if not value or "=" in value:
        raise CryptoError("base64url value must be non-empty and unpadded")
    try:
        raw = value.encode("ascii")
        decoded = base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CryptoError("invalid base64url value") from exc
    if b64url_encode(decoded) != value:
        raise CryptoError("base64url value is not canonical")
    if len(decoded) != expected_length:
        raise CryptoError(f"decoded value must be {expected_length} bytes")
    return decoded


def public_key_from_text(value: str) -> Ed25519PublicKey:
    raw = b64url_decode(value, expected_length=32)
    if not crypto_core_ed25519_is_valid_point(raw):
        raise CryptoError("Ed25519 public key must be canonical and in the prime-order subgroup")
    return Ed25519PublicKey.from_public_bytes(raw)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (TypeError, UnsupportedAlgorithm, ValueError) as exc:
        raise CryptoError("private key must be valid unencrypted PKCS#8 PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise CryptoError("private key must be Ed25519 PKCS#8 PEM")
    return key


def public_key_text(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64url_encode(raw)


def signature_payload(document: dict[str, Any]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical_bytes(unsigned)


def sign_document(
    document: dict[str, Any], private_key: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    signed = dict(document)
    signed.pop("signature", None)
    signature = private_key.sign(canonical_bytes(signed))
    signed["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": b64url_encode(signature),
    }
    return signed


def verify_document(document: dict[str, Any], public_key_text_value: str) -> bool:
    signature = document.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return False
    try:
        raw = b64url_decode(signature.get("value", ""), expected_length=64)
        raw_public_key = b64url_decode(public_key_text_value, expected_length=32)
        if not crypto_core_ed25519_is_valid_point(raw_public_key):
            return False
        VerifyKey(raw_public_key).verify(signature_payload(document), raw)
    except (BadSignatureError, CryptoError, TypeError, ValueError):
        return False
    return True


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    private_target = Path(private_path)
    public_target = Path(public_path)
    if private_target.resolve() == public_target.resolve():
        raise CryptoError("private and public key paths must be different")
    if private_target.exists() or public_target.exists():
        raise CryptoError("refusing to overwrite an existing key file")
    private_target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    public_target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_descriptor = os.open(private_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(private_descriptor, "wb") as handle:
        handle.write(pem)
    try:
        public_descriptor = os.open(public_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except OSError:
        private_target.unlink(missing_ok=True)
        raise
    with os.fdopen(public_descriptor, "w", encoding="ascii") as handle:
        handle.write(public_key_text(private_key) + "\n")
