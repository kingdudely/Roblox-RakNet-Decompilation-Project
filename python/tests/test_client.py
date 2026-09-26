"""Tests for Request1 construction and join metadata helpers."""

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rbxraknet.client import make_client_public_key_data
from rbxraknet.raknet import (
    DEFAULT_RUPP_OPT_IN,
    MAGIC,
    ID_RBX_OPEN_REPLY_1,
    ID_RBX_OPEN_REQUEST_1,
    ID_RBX_OPEN_REQUEST_2,
    ID_RBX_OPEN_REPLY_2,
    RBX_OPEN_PROTOCOL,
    RakNetClient,
    REQUEST1_LEN,
)


def test_x25519_shape():
    local = X25519PrivateKey.generate()
    peer = X25519PrivateKey.generate()
    assert local.exchange(peer.public_key()) == peer.exchange(local.public_key())


def test_client_public_key_data_defaults_to_version_2():
    key = bytes(range(32))
    text = make_client_public_key_data(key)
    assert '"RakNetEarlyPublicKey"' in text
    assert '"id":2' in text
    assert base64.b64encode(key).decode() in text


def test_current_rbx_open_request1_shape():
    client = RakNetClient("127.0.0.1", 1234, rupp_opt_in=DEFAULT_RUPP_OPT_IN)
    try:
        request1 = client.build_open_request_1()
        assert len(request1) == REQUEST1_LEN
        assert request1[0] == ID_RBX_OPEN_REQUEST_1
        assert request1[1:17] == MAGIC
        assert request1[17] == RBX_OPEN_PROTOCOL
        assert request1[18] == DEFAULT_RUPP_OPT_IN
        assert request1[19:] == bytes(len(request1) - 19)
    finally:
        client.close()


def test_current_packet_ids():
    assert ID_RBX_OPEN_REPLY_1 == 0x7E
    assert ID_RBX_OPEN_REQUEST_2 == 0x78
    assert ID_RBX_OPEN_REPLY_2 == 0x7D