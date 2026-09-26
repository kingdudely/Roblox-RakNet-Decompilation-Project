"""Minimal Roblox RakNet bring-up client.

This module intentionally stops at the protocol pieces that are actually established
in the fork:

    .ROBLOSECURITY
        -> auth ticket
        -> GameJoin joinScript
        -> local X25519 keypair
        -> X25519(shared secret)
        -> SHA-512(shared || local_public || peer_public)
        -> UDP/UDMUX probe
        -> optional live AEAD candidate test

The last two transport secrets are not guessed as solved facts:
the exact 64-byte digest -> {tx, rx} mapping and epoch rekey are still unresolved,
and the separate Rupp packet-token generator is unresolved.

No cookie, authentication ticket, client private key, or session key is printed.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .aead import AeadCodec, AES, CHACHA
from .framing import parse as parse_frame
from .inner import decode_inner

AUTH_TICKET_URL = "https://auth.roblox.com/v1/authentication-ticket"
JOIN_GAME_URL = "https://gamejoin.roblox.com/v1/join-game"
JOIN_INSTANCE_URL = "https://gamejoin.roblox.com/v1/join-game-instance"
SERVERS_URL = "https://games.roblox.com/v1/games/{}/servers/0?sortOrder=2&excludeFullGames=false&limit=10"

RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")


def _b64decode(value: str) -> bytes:
    value = value.strip()
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except Exception as exc:
        raise ValueError("invalid base64 join field") from exc


def _http(
    url: str,
    *,
    cookie: str | None = None,
    csrf: str | None = None,
    ticket: str | None = None,
    method: str = "POST",
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    headers = {
        "User-Agent": "Roblox/WinInet",
        "Accept": "application/json",
        "Origin": "https://www.roblox.com",
        "Referer": "https://www.roblox.com/",
    }
    if cookie:
        headers["Cookie"] = f".ROBLOSECURITY={cookie}"
    if csrf:
        headers["X-CSRF-TOKEN"] = csrf
    if ticket:
        headers["RBX-Authentication-Ticket"] = ticket
        headers["RBXAuthenticationNegotiation"] = "1"
    if body is not None:
        headers["Content-Type"] = "application/json"

    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=20) as response:
            hdrs = {k.lower(): v.strip() for k, v in response.headers.items()}
            return response.status, hdrs, response.read()
    except HTTPError as exc:
        hdrs = {k.lower(): v.strip() for k, v in exc.headers.items()}
        data = exc.read()
        return exc.code, hdrs, data
    except URLError as exc:
        raise RuntimeError(f"HTTP request failed: {exc.reason}") from exc


def _csrf(cookie: str) -> str:
    status, headers, _ = _http(
        AUTH_TICKET_URL,
        cookie=cookie,
        method="POST",
        body=b"",
    )
    token = headers.get("x-csrf-token")
    if not token:
        raise RuntimeError(
            f"Roblox did not return X-CSRF-TOKEN (HTTP {status}). "
            "The cookie may be invalid/expired or the endpoint may have changed."
        )
    return token


def _authentication_ticket(cookie: str, csrf: str) -> str:
    status, headers, body = _http(
        AUTH_TICKET_URL,
        cookie=cookie,
        csrf=csrf,
        method="POST",
        body=b"",
    )
    ticket = headers.get("rbx-authentication-ticket")
    if not ticket:
        detail = body.decode("utf-8", "replace")[:300]
        raise RuntimeError(f"no RBX-Authentication-Ticket (HTTP {status}): {detail}")
    return ticket


def _client_public_key_data(public_key: bytes, version_id: int) -> str:
    value = base64.b64encode(public_key).decode("ascii")
    app = {
        "versions": [{"id": version_id, "value": value, "allowed": True}],
        "send": version_id,
        "revert": version_id,
    }
    return json.dumps(
        {
            "applications": {"RakNetEarlyPublicKey": app},
        },
        separators=(",", ":"),
    )


def _get_first_server(place_id: int) -> str | None:
    url = SERVERS_URL.format(place_id)
    status, _, body = _http(url, method="GET")
    if status != 200:
        raise RuntimeError(f"server list failed (HTTP {status})")
    data = json.loads(body)
    for server in data.get("data", []):
        job_id = server.get("id")
        if job_id:
            return job_id
    return None


@dataclass(frozen=True)
class JoinResult:
    join_script: dict[str, Any]
    auth_ticket: str
    local_public: bytes
    shared_secret: bytes
    kdf_digest: bytes

    @property
    def endpoints(self) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for item in self.join_script.get("UdmuxEndpoints", []) or []:
            if item.get("Address") and item.get("Port"):
                out.append((str(item["Address"]), int(item["Port"])))
        return out


class RobloxJoinClient:
    def __init__(self, cookie: str):
        if not cookie:
            raise ValueError("empty ROBLOSECURITY")
        self.cookie = cookie

    def join(
        self,
        place_id: int,
        game_id: str | None = None,
        public_key_version: int = 2,
    ) -> JoinResult:
        private = X25519PrivateKey.generate()
        local_public = private.public_key().public_bytes_raw()
        csrf = _csrf(self.cookie)
        auth_ticket = _authentication_ticket(self.cookie, csrf)

        if game_id is None:
            game_id = _get_first_server(place_id)

        body: dict[str, Any] = {
            "placeId": place_id,
            "isTeleport": False,
            "gameJoinAttemptId": str(uuid.uuid4()),
            "ClientPublicKeyData": _client_public_key_data(local_public, public_key_version),
        }
        if game_id:
            body["gameId"] = game_id

        endpoint = JOIN_INSTANCE_URL if game_id else JOIN_GAME_URL
        status, _, raw = _http(
            endpoint,
            cookie=self.cookie,
            csrf=csrf,
            ticket=auth_ticket,
            body=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        )
        if status != 200:
            detail = raw.decode("utf-8", "replace")[:500]
            raise RuntimeError(f"join request failed (HTTP {status}): {detail}")

        response = json.loads(raw)
        if response.get("status") not in (None, 2):
            raise RuntimeError(
                f"GameJoin returned status={response.get('status')}: "
                f"{response.get('message', '')}"
            )

        join_script = response.get("joinScript") or {}
        if not isinstance(join_script, dict):
            raise RuntimeError("joinScript missing or malformed")

        peer_raw = join_script.get("EphemeralEarlyPubKey")
        if not peer_raw:
            raise RuntimeError("joinScript has no EphemeralEarlyPubKey")

        peer_public = _b64decode(str(peer_raw))
        if len(peer_public) != 32:
            raise RuntimeError(
                f"EphemeralEarlyPubKey decoded to {len(peer_public)} bytes, expected 32"
            )

        peer = X25519PublicKey.from_public_bytes(peer_public)
        shared = private.exchange(peer)

        # Exact construction documented by the fork's IDA notes.
        digest = hashlib.sha512(shared + local_public + peer_public).digest()

        return JoinResult(
            join_script=join_script,
            auth_ticket=auth_ticket,
            local_public=local_public,
            shared_secret=shared,
            kdf_digest=digest,
        )


def _print_join(result: JoinResult) -> None:
    js = result.join_script
    print(f"join ok: place={js.get('PlaceId')} user={js.get('UserName')}")
    print(f"job: {js.get('GameId') or 'unknown'}")
    print(f"udmux endpoints: {len(result.endpoints)}")
    for address, port in result.endpoints:
        print(f"  {address}:{port}")
    print(f"X25519: shared secret = {len(result.shared_secret)} bytes")
    print(f"SHA-512 KDF candidate = {len(result.kdf_digest)} bytes")
    print(
        "note: digest -> direction keys is NOT treated as solved; "
        "the branch only tests candidate splits."
    )


def _unconnected_ping(guid: int) -> bytes:
    return b"\x01" + int(time.time() * 1000).to_bytes(8, "big") + RAKNET_MAGIC + guid.to_bytes(8, "big")


def udp_probe(
    endpoint: tuple[str, int],
    *,
    timeout: float = 3.0,
) -> list[bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    guid = int.from_bytes(os.urandom(8), "big")
    packet = _unconnected_ping(guid)
    try:
        sock.sendto(packet, endpoint)
        received: list[bytes] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            received.append(data)
            print(f"udp reply from {addr[0]}:{addr[1]} len={len(data)} first=0x{data[0]:02x}")
        if not received:
            print("udp probe: no reply")
        return received
    finally:
        sock.close()


def _candidate_key_pairs(digest: bytes) -> list[tuple[str, bytes, bytes]]:
    return [
        ("digest[0:32] -> 0x17, digest[32:64] -> 0x1f", digest[:32], digest[32:]),
        ("digest[32:64] -> 0x17, digest[0:32] -> 0x1f", digest[32:], digest[:32]),
    ]


def try_live_decrypt(
    result: JoinResult,
    *,
    timeout: float = 8.0,
    span: int = 2,
) -> int:
    if not result.endpoints:
        print("live decrypt: no UDMUX endpoint in joinScript")
        return 1

    print("live decrypt: listening for UDMUX packets; no private/session material is printed")
    endpoint = result.endpoints[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    guid = int.from_bytes(os.urandom(8), "big")
    sock.sendto(_unconnected_ping(guid), endpoint)

    codecs: list[tuple[str, int, AeadCodec]] = []
    for name, key17, key1f in _candidate_key_pairs(result.kdf_digest):
        for direction, key in ((0x17, key17), (0x1F, key1f)):
            for cipher in (AES, CHACHA):
                codecs.append((f"{name}; dir=0x{direction:02x}; {cipher}", direction, AeadCodec(key, cipher)))

    successes = 0
    frames = 0
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue

            if not data:
                continue

            try:
                frame = parse_frame(data)
            except ValueError:
                continue

            frames += 1
            authenticated = False
            for label, direction, codec in codecs:
                if frame.direction != direction:
                    continue
                pt, counter = codec.decrypt(frame, span=span)
                if pt is None:
                    continue

                authenticated = True
                successes += 1
                tree = decode_inner(pt)
                print(
                    f"DECRYPT OK: {label} counter={counter} "
                    f"inner={tree.get('type')} bytes={len(pt)}"
                )
                if tree.get("type") == "DATA":
                    print(
                        f"  datagram={tree.get('datagram_number')} "
                        f"messages={len(tree.get('messages', []))}"
                    )
                break

            if not authenticated:
                print(
                    f"UDMUX frame received: dir=0x{frame.direction:02x}, "
                    f"epoch={frame.epoch_tag.hex()}, "
                    "candidate key did not authenticate"
                )
    finally:
        sock.close()

    print(f"live decrypt summary: frames={frames}, authenticated={successes}")
    if successes == 0:
        print(
            "No packet authenticated. This is expected until the SHA-512 digest "
            "split/epoch derivation is confirmed (or a known session key is supplied)."
        )
        return 2
    return 0


def _read_cookie() -> str:
    cookie = os.environ.get("ROBLOSECURITY")
    if cookie:
        return cookie.strip()
    return getpass.getpass("ROBLOSECURITY: ").strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Minimal Roblox RakNet bring-up test")
    ap.add_argument("--place-id", type=int, required=True)
    ap.add_argument("--job-id", help="optional server/job UUID; otherwise pick the first public server")
    ap.add_argument(
        "--public-key-version",
        type=int,
        default=2,
        help="RakNetEarlyPublicKey version id used by the current fork notes (default: 2)",
    )
    ap.add_argument("--probe", action="store_true", help="send an unconnected RakNet ping to the UDMUX endpoint")
    ap.add_argument("--decrypt", action="store_true", help="listen and test the currently-known KDF candidate keys")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--span", type=int, default=2)
    args = ap.parse_args(argv)

    cookie = _read_cookie()
    if not cookie:
        print("missing ROBLOSECURITY", file=sys.stderr)
        return 2

    client = RobloxJoinClient(cookie)
    try:
        result = client.join(
            args.place_id,
            game_id=args.job_id,
            public_key_version=args.public_key_version,
        )
    except Exception as exc:
        print(f"join failed: {exc}", file=sys.stderr)
        return 1

    _print_join(result)

    if not (args.probe or args.decrypt):
        return 0

    if not result.endpoints:
        print("no UDMUX endpoint to test", file=sys.stderr)
        return 1

    if args.probe:
        endpoint = result.endpoints[0]
        print(f"udp probe -> {endpoint[0]}:{endpoint[1]}")
        udp_probe(endpoint, timeout=args.timeout)

    if args.decrypt:
        return try_live_decrypt(result, timeout=args.timeout, span=args.span)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
