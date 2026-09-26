"""Tests for the live-join bring-up pieces."""

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rbxraknet.client import make_client_public_key_data
from rbxraknet.raknet import MAGIC, RakNetClient


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


def test_raknet_packet_shapes():
    client = RakNetClient("127.0.0.1", 1234)
    try:
        assert client.build_unconnected_ping()[0] == 0x01
        request1 = client._open_request_1()
        assert len(request1) == client.mtu
        assert request1[1:17] == MAGIC
        request2 = client._open_request_2("127.0.0.1", 1234, client.mtu)
        assert request2[0] == 0x07
        assert request2[1:17] == MAGIC
    finally:
        client.close()
