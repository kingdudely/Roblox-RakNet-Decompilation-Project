"""Tests for the live-join bring-up pieces."""

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rbxraknet.client import make_client_public_key_data
from rbxraknet.raknet import (
    MAGIC,
    ID_RBX_OPEN_REPLY_1,
    ID_RBX_OPEN_REQUEST_1,
    ID_RBX_OPEN_REQUEST_2,
    ID_RBX_OPEN_REPLY_2,
    RBX_OPEN_PROTOCOL,
    RakNetClient,
    REQUEST1_LEN,
)


def test_x25519_and_sha512_shape():
    local = X25519PrivateKey.generate()
    peer = X25519PrivateKey.generate()

    lp = local.public_key().public_bytes_raw()
    pp = peer.public_key().public_bytes_raw()

    a = local.exchange(peer.public_key())
    b = peer.exchange(local.public_key())
    assert a == b

    digest = hashlib.sha512(a + lp + pp).digest()

    assert len(a) == 32
    assert len(digest) == 64


def test_client_public_key_data():
    key = bytes(range(32))
    text = make_client_public_key_data(key, 2)
    assert '"RakNetEarlyPublicKey"' in text
    assert base64.b64encode(key).decode() in text


def test_current_rbx_open_request1_shape():
    client = RakNetClient("127.0.0.1", 1234)
    try:
        request1 = client.build_open_request_1()
        assert len(request1) == REQUEST1_LEN
        assert request1[0] == ID_RBX_OPEN_REQUEST_1
        assert request1[1:17] == MAGIC
        assert request1[17] == RBX_OPEN_PROTOCOL
        assert request1[18] == 1  # Rupp opt-in enabled by the canonical client.
        assert request1[19:] == bytes(len(request1) - 19)
    finally:
        client.close()


def test_current_packet_ids():
    assert ID_RBX_OPEN_REPLY_1 == 0x7E
    assert ID_RBX_OPEN_REQUEST_2 == 0x78
    assert ID_RBX_OPEN_REPLY_2 == 0x7D
