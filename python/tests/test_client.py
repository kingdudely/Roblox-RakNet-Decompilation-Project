"""Offline self-tests for the Python bring-up path."""

import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .client import _candidate_key_pairs, _client_public_key_data
from .framing import FLAG, SUBFLAGS, parse
from .aead import AeadCodec, AES, COUNTER_BASE, nonce
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_x25519_and_kdf_shape():
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    ap = a.public_key().public_bytes_raw()
    bp = b.public_key().public_bytes_raw()
    s1 = a.exchange(b.public_key())
    s2 = b.exchange(a.public_key())
    assert s1 == s2
    digest = hashlib.sha512(s1 + ap + bp).digest()
    pairs = _candidate_key_pairs(digest)
    assert len(s1) == 32 and len(digest) == 64
    assert len(pairs) == 2
    assert all(len(k1) == 32 and len(k2) == 32 for _, k1, k2 in pairs)


def test_client_public_key_data():
    key = bytes(range(32))
    value = _client_public_key_data(key, 2)
    assert '"RakNetEarlyPublicKey"' in value
    assert '"id":2' in value


def test_outer_and_aead():
    key = bytes(range(32))
    plaintext = b"test"
    counter = COUNTER_BASE + 7
    blob = AESGCM(key).encrypt(nonce(counter), plaintext, b"")
    payload = (
        bytes((FLAG, 0, 0, 0x17))
        + SUBFLAGS
        + bytes(16)
        + blob[:-16]
        + (counter & 0xFFFF).to_bytes(2, "little")
        + blob[-16:]
    )
    dg = parse(payload)
    pt, got = AeadCodec(key, AES).decrypt(dg, span=1)
    assert pt == plaintext
    assert got == counter
