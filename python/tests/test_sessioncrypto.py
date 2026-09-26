"""Tests for the build-specific SessionCrypto primitives."""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rbxraknet.sessioncrypto import (
    COUNTER_BASE,
    counter_from_hint,
    derive_session_digest,
    nonce,
)


def test_post_ecdh_sha512_shape():
    local = X25519PrivateKey.generate()
    peer = X25519PrivateKey.generate()

    result = derive_session_digest(
        local,
        peer.public_key().public_bytes_raw(),
    )

    assert len(result.local_public) == 32
    assert len(result.peer_public) == 32
    assert len(result.shared_secret) == 32
    assert len(result.digest) == 64
    assert result.left + result.right == result.digest


def test_nonce_base_is_unique_number():
    assert nonce(COUNTER_BASE) == b"UniqueNumbeR"


def test_counter_hint_wrap():
    counter = COUNTER_BASE + 70000
    assert counter_from_hint(counter & 0xFFFF, last=counter - 100) == counter
