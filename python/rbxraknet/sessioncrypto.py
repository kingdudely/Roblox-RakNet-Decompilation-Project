"""Build-specific Roblox SessionCrypto primitives supported by current IDA evidence.

Target: Roblox Player 9.4.260915.1d72b8c0 (x86-64).

What is established:
    shared = X25519(local_private, peer_public)
    digest = SHA512(shared || local_public || peer_public)

The 64-byte digest is intentionally returned without assigning transmit/receive
keys. The key split and epoch rekey are still unresolved and must not be guessed.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

NONCE_SUFFIX = b"mbeR"
NONCE_PREFIX = b"UniqueNu"
COUNTER_BASE = int.from_bytes(NONCE_PREFIX, "little")


@dataclass(frozen=True)
class SessionKdfResult:
    local_public: bytes
    peer_public: bytes
    shared_secret: bytes
    digest: bytes

    @property
    def left(self) -> bytes:
        """First 32 bytes of the confirmed 64-byte SHA-512 result.

        This is a digest half only, not a claimed packet key.
        """
        return self.digest[:32]

    @property
    def right(self) -> bytes:
        """Last 32 bytes of the confirmed 64-byte SHA-512 result.

        This is a digest half only, not a claimed packet key.
        """
        return self.digest[32:]


def derive_session_digest(
    private_key: X25519PrivateKey,
    peer_public: bytes,
) -> SessionKdfResult:
    """Reproduce the confirmed post-ECDH derivation shape."""
    if len(peer_public) != 32:
        raise ValueError("peer_public must be exactly 32 bytes")

    local_public = private_key.public_key().public_bytes_raw()
    peer = X25519PublicKey.from_public_bytes(peer_public)
    shared = private_key.exchange(peer)
    digest = hashlib.sha512(shared + local_public + peer_public).digest()

    return SessionKdfResult(
        local_public=local_public,
        peer_public=peer_public,
        shared_secret=shared,
        digest=digest,
    )


def nonce(counter: int) -> bytes:
    """Build the confirmed 12-byte SessionCrypto nonce."""
    if not 0 <= counter < (1 << 64):
        raise ValueError("counter must fit in uint64")
    return struct.pack("<Q", counter) + NONCE_SUFFIX


def counter_from_hint(hint: int, last: int | None = None) -> int:
    """Resolve a 16-bit wire hint near the supplied counter.

    With no prior counter, resolution starts at the confirmed UniqueNu base.
    """
    if not 0 <= hint <= 0xFFFF:
        raise ValueError("hint must be a uint16")

    reference = COUNTER_BASE if last is None else last
    base = (reference & ~0xFFFF) | hint
    candidates = (base - 0x10000, base, base + 0x10000)
    return min(candidates, key=lambda value: abs(value - reference))


def _selftest() -> None:
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()

    ar = derive_session_digest(a, b.public_key().public_bytes_raw())
    br = derive_session_digest(b, a.public_key().public_bytes_raw())

    assert ar.shared_secret == br.shared_secret
    assert ar.local_public != ar.peer_public
    assert len(ar.digest) == 64
    assert len(ar.left) == 32 and len(ar.right) == 32
    assert nonce(COUNTER_BASE) == b"UniqueNumbeR"

    c = COUNTER_BASE + 70000
    hint = c & 0xFFFF
    assert counter_from_hint(hint, last=c - 100) == c

    print("[sessioncrypto] selftest OK")


if __name__ == "__main__":
    _selftest()
