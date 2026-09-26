"""Roblox current pre-auth RakNet-style connection handshake.

This module is intentionally limited to Request1/Reply1. Request1 field values are
partially build-specific and must be verified against the target Android libroblox.so.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")

ID_RBX_OPEN_REQUEST_1 = 0x7B
ID_RBX_OPEN_REPLY_1 = 0x7E
ID_RBX_OPEN_REQUEST_2 = 0x78
ID_RBX_OPEN_REPLY_2 = 0x7D

RBX_OPEN_PROTOCOL = 5
DEFAULT_MTU = 1492
DEFAULT_RUPP_OPT_IN = 0
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
        rupp_opt_in: int = DEFAULT_RUPP_OPT_IN,
        local_port: int = 0,
    ):
        self.endpoint = (host, int(port))
        self.timeout = timeout
        self.mtu = int(mtu)
        self.rupp_opt_in = int(rupp_opt_in)
        if self.mtu < 576:
            raise ValueError("MTU must be at least 576")
        if self.rupp_opt_in not in (0, 1):
            raise ValueError("rupp_opt_in must be 0 or 1")

        infos = socket.getaddrinfo(
            host,
            int(port),
            type=socket.SOCK_DGRAM,
        )
        if not infos:
            raise OSError(f"could not resolve UDP endpoint {host}:{port}")
        family, socktype, proto, _, sockaddr = infos[0]
        self.family = family
        self.sock = socket.socket(family, socktype, proto)
        self.sock.settimeout(timeout)
        if local_port:
            bind_host = "::" if family == socket.AF_INET6 else "0.0.0.0"
            self.sock.bind((bind_host, int(local_port)))
        self.endpoint = sockaddr

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
        # Existing Windows IDA notes identify the constructor as being called
        # with MTU - 40. This length is NOT yet independently confirmed on the
        # Android x86-64 target.
        total = self.mtu - 40
        prefix = bytes((ID_RBX_OPEN_REQUEST_1,)) + MAGIC + bytes((
            RBX_OPEN_PROTOCOL,
            self.rupp_opt_in,
        ))
        if total < len(prefix):
            raise RakNetError("requested MTU is too small for RbxOpenRequest1")
        return prefix + bytes(total - len(prefix))

    def connect(self, *, trace: bool = False) -> RbxOpenReply1:
        request1 = self.build_open_request_1()
        if trace:
            local = self.sock.getsockname()
            print(
                f"UDP -> {self.endpoint!r} from {local!r} "
                f"RbxOpenRequest1=0x{ID_RBX_OPEN_REQUEST_1:02x} "
                f"len={len(request1)} rupp_opt_in={self.rupp_opt_in} "
                f"prefix={request1[:32].hex()}"
            )
        self.sock.sendto(request1, self.endpoint)

        reply = self._recv()
        if trace:
            print(
                f"UDP <- packet=0x{reply[0]:02x} len={len(reply)} "
                f"prefix={reply[:128].hex()}"
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
        assert request1[18] == DEFAULT_RUPP_OPT_IN
        assert request1[19:] == bytes(len(request1) - 19)
        assert ID_RBX_OPEN_REPLY_1 == 0x7E
        assert ID_RBX_OPEN_REQUEST_2 == 0x78
        assert ID_RBX_OPEN_REPLY_2 == 0x7D
    finally:
        client.close()
    print("[raknet] selftest OK")


if __name__ == "__main__":
    _selftest()
