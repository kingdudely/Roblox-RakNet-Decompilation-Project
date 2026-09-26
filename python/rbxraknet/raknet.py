"""Small standard RakNet connection-negotiation client.

This is only the standard RakNet offline/online connection setup. It does not
implement Roblox's encrypted application session.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")

ID_UNCONNECTED_PING = 0x01
ID_OPEN_CONNECTION_REQUEST_1 = 0x7B
ID_OPEN_CONNECTION_REPLY_1 = 0x7E
ID_OPEN_CONNECTION_REQUEST_2 = 0x78
ID_OPEN_CONNECTION_REPLY_2 = 0x7D
ID_CONNECTION_REQUEST = 0x09
ID_CONNECTION_REQUEST_ACCEPTED = 0x10
ID_NEW_INCOMING_CONNECTION = 0x13
ID_ALREADY_CONNECTED = 0x12
ID_CONNECTION_BANNED = 0x17
ID_INCOMPATIBLE_PROTOCOL = 0x19

DEFAULT_PROTOCOL = 5
DEFAULT_MTU = 1492

# Roblox's custom open-connection packets carry the regular RakNet fields plus
# these client capability fields. These constants come from the public
# raknet-dissector implementation of the Roblox handshake.
CAPABILITY_ROBLOX = (
    (0x3E | 0x80)       # CapabilityBasic
    | 0x40              # CapabilityServerCopiesPlayerGui3
    | 0x400             # CapabilityIHasMinDistToUnstreamed
    | 0x800             # CapabilityReplicateLuau
    | 0x2000             # CapabilityVersionedIDSync
)
SUPPORTED_VERSION = 0


class RakNetError(RuntimeError):
    pass


@dataclass(frozen=True)
class HandshakeResult:
    server_guid: int
    mtu: int
    use_encryption: bool


def _ipv4_address(host: str, port: int) -> bytes:
    try:
        octets = [int(part) for part in host.split(".")]
    except ValueError as exc:
        raise RakNetError("UDMUX endpoint must currently be an IPv4 address") from exc
    if len(octets) != 4 or any(not 0 <= x <= 255 for x in octets):
        raise RakNetError("invalid IPv4 endpoint")
    return b"\x04" + bytes(octets) + struct.pack(">H", port)


class RakNetClient:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 4.0,
        protocol: int = DEFAULT_PROTOCOL,
        mtu: int = DEFAULT_MTU,
    ):
        self.endpoint = (host, int(port))
        self.timeout = timeout
        self.protocol = protocol
        self.mtu = mtu
        self.guid = int.from_bytes(os.urandom(8), "big")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def close(self) -> None:
        self.sock.close()

    def _recv(self) -> bytes:
        try:
            data, _ = self.sock.recvfrom(65535)
        except socket.timeout as exc:
            raise RakNetError("timeout waiting for a RakNet response") from exc
        if not data:
            raise RakNetError("received an empty UDP datagram")
        return data

    def build_unconnected_ping(self) -> bytes:
        now_ms = int(time.time() * 1000)
        return (
            bytes([ID_UNCONNECTED_PING])
            + struct.pack(">Q", now_ms)
            + MAGIC
            + struct.pack(">Q", self.guid)
        )

    def _open_request_1(self) -> bytes:
        # ID + magic + protocol byte + zero MTU padding.
        return (
            bytes([ID_OPEN_CONNECTION_REQUEST_1])
            + MAGIC
            + bytes([self.protocol & 0xFF])
            + bytes(max(0, self.mtu - 18))
        )

    def _open_request_2(self, host: str, port: int, mtu: int) -> bytes:
        return (
            bytes([ID_OPEN_CONNECTION_REQUEST_2])
            + MAGIC
            + _ipv4_address(host, port)
            + struct.pack(">H", mtu)
            + struct.pack(">Q", self.guid)
            + struct.pack(">I", SUPPORTED_VERSION)
            + struct.pack(">Q", CAPABILITY_ROBLOX)
        )

    def _connection_request(self) -> bytes:
        now_ms = int(time.time() * 1000)
        # The retail Roblox client uses a non-empty connection password on this
        # pre-authenticated RakNet path.
        password = bytes.fromhex("374f5e116c45")
        return (
            bytes([ID_CONNECTION_REQUEST])
            + struct.pack(">Q", self.guid)
            + struct.pack(">Q", now_ms)
            + b"\x00"  # useSecurity=false
            + password
        )

    def probe(self) -> bytes | None:
        self.sock.sendto(self.build_unconnected_ping(), self.endpoint)
        try:
            return self._recv()
        except RakNetError:
            return None

    def connect(self, *, trace: bool = False) -> HandshakeResult:
        host, port = self.endpoint

        request1 = self._open_request_1()
        if trace:
            print(f"UDP -> OPEN_CONNECTION_REQUEST_1 len={len(request1)}")
        self.sock.sendto(request1, self.endpoint)
        reply1 = self._recv()
        if trace:
            print(f"UDP <- packet=0x{reply1[0]:02x} len={len(reply1)} hex={reply1[:64].hex()}")
        if reply1[0] != ID_OPEN_CONNECTION_REPLY_1:
            raise RakNetError(f"expected 0x7e, got 0x{reply1[0]:02x}")
        if len(reply1) < 28 or reply1[1:17] != MAGIC:
            raise RakNetError("malformed OPEN_CONNECTION_REPLY_1")

        server_guid = struct.unpack(">Q", reply1[17:25])[0]
        use_security = bool(reply1[25])
        reply_mtu = struct.unpack(">H", reply1[26:28])[0]
        mtu = min(self.mtu, reply_mtu or self.mtu)

        request2 = self._open_request_2(host, port, mtu)
        if trace:
            print(f"UDP -> OPEN_CONNECTION_REQUEST_2 len={len(request2)}")
        self.sock.sendto(request2, self.endpoint)
        reply2 = self._recv()
        if trace:
            print(f"UDP <- packet=0x{reply2[0]:02x} len={len(reply2)} hex={reply2[:64].hex()}")
        if reply2[0] != ID_OPEN_CONNECTION_REPLY_2:
            raise RakNetError(f"expected 0x7d, got 0x{reply2[0]:02x}")
        if len(reply2) < 1 + 16 + 8 + 7 + 2 + 1 or reply2[1:17] != MAGIC:
            raise RakNetError("malformed OPEN_CONNECTION_REPLY_2")

        use_encryption = bool(reply2[-1])
        request = self._connection_request()
        if trace:
            print(f"UDP -> CONNECTION_REQUEST len={len(request)} hex={request.hex()}")
        self.sock.sendto(request, self.endpoint)

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                packet = self._recv()
            except RakNetError:
                continue
            code = packet[0]
            if trace:
                print(f"UDP <- packet=0x{code:02x} len={len(packet)} hex={packet[:128].hex()}")
            if code == ID_CONNECTION_REQUEST_ACCEPTED:
                result = HandshakeResult(server_guid, mtu, use_encryption or use_security)
                if trace:
                    self._trace_post_handshake()
                return result
            if code == ID_NEW_INCOMING_CONNECTION:
                result = HandshakeResult(server_guid, mtu, use_encryption or use_security)
                if trace:
                    self._trace_post_handshake()
                return result
            if code in (
                ID_ALREADY_CONNECTED,
                ID_CONNECTION_BANNED,
                ID_INCOMPATIBLE_PROTOCOL,
            ):
                raise RakNetError(f"server rejected connection with packet 0x{code:02x}")

        raise RakNetError("timeout waiting for connection acceptance")



    def _trace_post_handshake(self, seconds: float = 2.0) -> None:
        """Observe raw packets immediately after RakNet accepts the connection."""
        deadline = time.monotonic() + seconds
        previous_timeout = self.sock.gettimeout()
        try:
            while time.monotonic() < deadline:
                remaining = max(0.05, deadline - time.monotonic())
                self.sock.settimeout(min(previous_timeout or remaining, remaining))
                try:
                    packet = self._recv()
                except RakNetError:
                    break
                print(
                    f"UDP <- post-handshake packet=0x{packet[0]:02x} "
                    f"len={len(packet)} hex={packet[:128].hex()}"
                )
        finally:
            self.sock.settimeout(previous_timeout)

def _selftest() -> None:
    client = RakNetClient("127.0.0.1", 1234)
    try:
        ping = client.build_unconnected_ping()
        assert ping[0] == ID_UNCONNECTED_PING
        request1 = client._open_request_1()
        assert len(request1) == DEFAULT_MTU
        assert request1[1:17] == MAGIC
        assert request1[0] == ID_OPEN_CONNECTION_REQUEST_1
        request2 = client._open_request_2("127.0.0.1", 1234, DEFAULT_MTU)
        assert request2[0] == ID_OPEN_CONNECTION_REQUEST_2
        assert request2[1:17] == MAGIC
        assert len(request2) == 46
    finally:
        client.close()
    print("[raknet] selftest OK")


if __name__ == "__main__":
    _selftest()
