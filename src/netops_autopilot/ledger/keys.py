"""Collector key registry (Ed25519).

D1 scope: in-memory registry with explicit key material injection points.
The Security Plane keychain binding (§18, OS keychain) lands in a later D1
batch; this module's interface (key_id-based signing, append-only public
registry) is already shaped for that move — engines only ever see key ids
through :func:`KeyRegistry.signer_for`.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from ..core.ids import new_id


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def canonical_bytes(payload: dict) -> bytes:
    """Canonical JSON for signing/hashing: sorted keys, no whitespace."""
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class _KeyPair:
    key_id: str
    private: Ed25519PrivateKey
    public_pem: bytes


class KeyRegistry:
    """Append-only collector-key registry.

    * ``create_key`` generates a pair and registers it.
    * ``signer_for(key_id)`` returns a signing callable (the only way to
      sign; private material is otherwise unreachable from callers).
    * ``verify`` checks a signature against the registered public key.
    * Public keys are immutable once registered; re-registration of a key_id
      is forbidden (append-only, rotation creates new ids).
    """

    def __init__(self) -> None:
        self._pairs: dict[str, _KeyPair] = {}

    def create_key(self, purpose: str = "collector") -> str:
        private = Ed25519PrivateKey.generate()
        public_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        # key id binds to purpose + public key fingerprint (stable, auditable).
        digest = hashlib.sha256(public_pem).hexdigest()[:16]
        key_id = f"{purpose}-{digest}"
        if key_id in self._pairs:  # pragma: no cover - sha256 collision guard
            raise ValueError("key id collision")
        self._pairs[key_id] = _KeyPair(key_id=key_id, private=private, public_pem=public_pem)
        return key_id

    def signer_for(self, key_id: str):
        pair = self._require(key_id)

        def sign(data: bytes) -> str:
            return b64(pair.private.sign(data))

        return sign

    def verify(self, key_id: str, data: bytes, signature_b64: str) -> bool:
        pair = self._require(key_id)
        try:
            pair_private: Ed25519PublicKey = pair.private.public_key()
            pair_private.verify(unb64(signature_b64), data)
            return True
        except Exception:
            return False

    def public_pem(self, key_id: str) -> bytes:
        return self._require(key_id).public_pem

    def _require(self, key_id: str) -> _KeyPair:
        try:
            return self._pairs[key_id]
        except KeyError:
            raise KeyError(f"unknown key_id: {key_id!r} (registry is append-only; was it rotated?)") from None
