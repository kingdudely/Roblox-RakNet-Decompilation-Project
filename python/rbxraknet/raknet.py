"""Roblox's current offline RakNet-style connection handshake.

This is not vanilla RakNet connection negotiation. The current Roblox client uses
RbxOpenRequest1/Reply1 (0x7B/0x7E) followed by encrypted RbxOpenRequest2/Reply2
(0x78/0x7D).

The Request2 serializer and SessionCrypto state machine are still being completed,
so this module currently brings the connection up only through Reply1.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")

ID_RBX_OPEN_REQUEST_1 = 0x7B
ID_RBX_OPEN_REPLY_1 = 0x7E
ID_RBX_OPEN_REQUEST_2 = 0x78
ID_RBX_OPEN_REPLY_2 = 0x7D

RBX_OPEN_PROTOCOL = 5
DEFAULT_MTU = 1492
REQUEST1_LEN = DEFAULT_MTU - 40


class RakNetError(RuntimeError):
    pass


@dataclass(frozen=True)
class RbxOpenReply1:
    raw: bytes


class RakNetClient:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 4.0,
        mtu: int = DEFAULT_MTU,
    ):
        self.endpoint = (host, int(port))
        self.timeout = timeout
        self.mtu = int(mtu)
        if self.mtu < 576:
            raise ValueError("MTU must be at least 576")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def close(self) -> None:
        self.sock.close()

    def _recv(self) -> bytes:
        try:
            data, _ = self.sock.recvfrom(65535)
        except socket.timeout as exc:
            raise RakNetError("timeout waiting for an RbxOpen reply") from exc
        if not data:
            raise RakNetError("received an empty UDP datagram")
        return data

    def build_open_request_1(self) -> bytes:
        # sub_2897560 is called with MTU - 40. The serializer writes:
        #   0x7B + 16-byte magic + protocol(5) + Rupp opt-in(0) + zero padding.
        total = self.mtu - 40
        prefix = bytes((ID_RBX_OPEN_REQUEST_1,)) + MAGIC + bytes((RBX_OPEN_PROTOCOL, 0))
        if total < len(prefix):
            raise RakNetError("requested MTU is too small for RbxOpenRequest1")
        return prefix + bytes(total - len(prefix))

    def probe(self) -> bytes | None:
        """Send RbxOpenRequest1 and return the raw RbxOpenReply1, if any."""
        self.sock.sendto(self.build_open_request_1(), self.endpoint)
        try:
            reply = self._recv()
        except RakNetError:
            return None
        if reply[0] != ID_RBX_OPEN_REPLY_1:
            return reply
        if len(reply) < 17 or reply[1:17] != MAGIC:
            raise RakNetError("RbxOpenReply1 has an invalid magic value")
        return reply

    def connect(self, *, trace: bool = False) -> RbxOpenReply1:
        request1 = self.build_open_request_1()
        if trace:
            print(
                f"UDP -> RbxOpenRequest1 0x{ID_RBX_OPEN_REQUEST_1:02x} "
                f"len={len(request1)}"
            )
        self.sock.sendto(request1, self.endpoint)

        reply = self._recv()
        if trace:
            print(
                f"UDP <- RbxOpenReply1 0x{reply[0]:02x} "
                f"len={len(reply)} hex={reply[:128].hex()}"
            )

        if reply[0] != ID_RBX_OPEN_REPLY_1:
            raise RakNetError(
                f"expected RbxOpenReply1 0x{ID_RBX_OPEN_REPLY_1:02x}, "
                f"got 0x{reply[0]:02x}"
            )
        if len(reply) < 17 or reply[1:17] != MAGIC:
            raise RakNetError("malformed RbxOpenReply1")

        return RbxOpenReply1(raw=reply)


def _selftest() -> None:
    client = RakNetClient("127.0.0.1", 1234)
    try:
        request1 = client.build_open_request_1()
        assert len(request1) == REQUEST1_LEN
        assert request1[0] == ID_RBX_OPEN_REQUEST_1
        assert request1[1:17] == MAGIC
        assert request1[17] == RBX_OPEN_PROTOCOL
        assert request1[18] == 0
        assert request1[19:] == bytes(len(request1) - 19)
        assert ID_RBX_OPEN_REPLY_1 == 0x7E
        assert ID_RBX_OPEN_REQUEST_2 == 0x78
        assert ID_RBX_OPEN_REPLY_2 == 0x7D
    finally:
        client.close()
    print("[raknet] selftest OK")


if __name__ == "__main__":
    _selftest()
