"""Minimal Roblox RakNet join/bring-up client.

Implemented stages:
    .ROBLOSECURITY -> X-CSRF -> auth ticket -> GameJoin joinScript
    -> local X25519 -> X25519(shared) -> SHA512(shared || pubs)

The exact AEAD key split/epoch KDF and Rupp token generator remain unresolved
in the current fork, so this module does not invent them.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .raknet import RakNetClient, RakNetError

AUTH_TICKET_URL = "https://auth.roblox.com/v1/authentication-ticket"
JOIN_GAME_URL = "https://gamejoin.roblox.com/v1/join-game"
JOIN_INSTANCE_URL = "https://gamejoin.roblox.com/v1/join-game-instance"
SERVERS_URL = "https://games.roblox.com/v1/games/{}/servers/0?sortOrder=2&excludeFullGames=false&limit=10"
DEFAULT_KEY_VERSION = 5


def _b64decode(value: str) -> bytes:
    value = value.strip()
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, validate=False)


def _http(url: str, *, cookie: str | None = None, csrf: str | None = None,
          ticket: str | None = None, negotiation: bool = False,
          method: str = "POST",
          body: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
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
    if ticket or negotiation:
        headers["RBXAuthenticationNegotiation"] = "1"
    if body is not None:
        headers["Content-Type"] = "application/json"

    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=20) as response:
            return response.status, {k.lower(): v.strip() for k, v in response.headers.items()}, response.read()
    except HTTPError as exc:
        return exc.code, {k.lower(): v.strip() for k, v in exc.headers.items()}, exc.read()
    except URLError as exc:
        raise RuntimeError(f"HTTP request failed: {exc.reason}") from exc


def get_csrf(cookie: str) -> str:
    status, headers, _ = _http(AUTH_TICKET_URL, cookie=cookie, body=b"")
    token = headers.get("x-csrf-token")
    if not token:
        raise RuntimeError(f"no X-CSRF-TOKEN returned (HTTP {status})")
    return token


def get_authentication_ticket(cookie: str, csrf: str) -> str:
    status, headers, body = _http(
        AUTH_TICKET_URL,
        cookie=cookie,
        csrf=csrf,
        body=b"",
        negotiation=True,
    )
    ticket = headers.get("rbx-authentication-ticket")
    if not ticket:
        detail = body.decode("utf-8", "replace")[:400]
        raise RuntimeError(f"no RBX-Authentication-Ticket (HTTP {status}): {detail}")
    return ticket


def make_client_public_key_data(public_key: bytes, version_id: int = DEFAULT_KEY_VERSION) -> str:
    encoded = base64.b64encode(public_key).decode("ascii")
    application = {
        "versions": [{"id": version_id, "value": encoded, "allowed": True}],
        "send": version_id,
        "revert": version_id,
    }
    return json.dumps(
        {"applications": {"RakNetEarlyPublicKey": application}},
        separators=(",", ":"),
    )


def get_first_public_job(place_id: int) -> str | None:
    status, _, raw = _http(SERVERS_URL.format(place_id), method="GET")
    if status != 200:
        raise RuntimeError(f"games server-list failed (HTTP {status})")
    data = json.loads(raw)
    for item in data.get("data", []):
        if item.get("id"):
            return str(item["id"])
    return None


@dataclass(frozen=True)
class JoinResult:
    join_script: dict[str, Any]
    auth_ticket: str
    local_public_key: bytes
    peer_public_key: bytes
    shared_secret: bytes
    sha512_digest: bytes

    @property
    def endpoints(self) -> list[tuple[str, int]]:
        return [
            (str(x["Address"]), int(x["Port"]))
            for x in (self.join_script.get("UdmuxEndpoints") or [])
            if x.get("Address") and x.get("Port")
        ]

    @property
    def client_ticket(self) -> str | None:
        value = self.join_script.get("ClientTicket")
        return str(value) if value else None


class RobloxJoinClient:
    def __init__(self, cookie: str):
        if not cookie:
            raise ValueError("ROBLOSECURITY is empty")
        self.cookie = cookie

    def join(self, place_id: int, *, job_id: str | None = None,
             public_key_version: int = DEFAULT_KEY_VERSION) -> JoinResult:
        private = X25519PrivateKey.generate()
        local_public = private.public_key().public_bytes_raw()
        csrf = get_csrf(self.cookie)
        auth_ticket = get_authentication_ticket(self.cookie, csrf)

        if job_id is None:
            job_id = get_first_public_job(place_id)

        body: dict[str, Any] = {
            "placeId": place_id,
            "isTeleport": False,
            "gameJoinAttemptId": str(uuid.uuid4()),
            "ClientPublicKeyData": make_client_public_key_data(local_public, public_key_version),
        }
        endpoint = JOIN_GAME_URL
        if job_id:
            body["gameId"] = job_id
            endpoint = JOIN_INSTANCE_URL

        status, _, raw = _http(
            endpoint,
            cookie=self.cookie,
            csrf=csrf,
            ticket=auth_ticket,
            body=json.dumps(body, separators=(",", ":")).encode(),
        )
        if status != 200:
            raise RuntimeError(
                f"GameJoin failed (HTTP {status}): "
                f"{raw.decode('utf-8', 'replace')[:500]}"
            )

        response = json.loads(raw)
        if response.get("status") not in (None, 2):
            raise RuntimeError(
                f"GameJoin status={response.get('status')}: {response.get('message', '')}"
            )

        join_script = response.get("joinScript") or {}
        if not isinstance(join_script, dict):
            raise RuntimeError("joinScript missing or malformed")

        peer_encoded = join_script.get("EphemeralEarlyPubKey")
        if not peer_encoded:
            raise RuntimeError("joinScript has no EphemeralEarlyPubKey")

        peer_encoded = str(peer_encoded)
        peer_public = _b64decode(peer_encoded)

        # Always expose the exact GameJoin value when the shape is unexpected.
        # This is a public key field, not the account cookie or authentication ticket.
        if len(peer_public) != 32:
            raise RuntimeError(
                "EphemeralEarlyPubKey decoded unexpectedly: "
                f"{len(peer_public)} bytes (expected 32); "
                f"base64={peer_encoded}; hex={peer_public.hex()}"
            )

        shared = private.exchange(X25519PublicKey.from_public_bytes(peer_public))
        digest = hashlib.sha512(shared + local_public + peer_public).digest()

        return JoinResult(
            join_script=join_script,
            auth_ticket=auth_ticket,
            local_public_key=local_public,
            peer_public_key=peer_public,
            shared_secret=shared,
            sha512_digest=digest,
        )


def print_join_summary(result: JoinResult) -> None:
    js = result.join_script
    print("joinScript: OK")
    print(f"  PlaceId: {js.get('PlaceId', '?')}")
    print(f"  GameId: {js.get('GameId', '?')}")
    print(f"  UserName: {js.get('UserName', '?')}")
    print(f"  ClientTicket: {'present' if result.client_ticket else 'missing'}")
    print(f"  UDMUX endpoints: {len(result.endpoints)}")
    for endpoint in result.endpoints:
        print(f"    {endpoint[0]}:{endpoint[1]}")
    print(f"X25519: OK ({len(result.shared_secret)} bytes)")
    print(f"SHA-512: OK ({len(result.sha512_digest)} bytes)")
    print("AEAD key split: unresolved")
    print("Epoch rekey: unresolved")
    print("Rupp token generator: unresolved")


def read_cookie() -> str:
    cookie = os.environ.get("ROBLOSECURITY")
    return cookie.strip() if cookie else getpass.getpass("ROBLOSECURITY: ").strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimal Roblox web-join + RakNet bring-up")
    parser.add_argument("--place-id", type=int, required=True)
    parser.add_argument("--job-id")
    parser.add_argument("--key-version", type=int, default=DEFAULT_KEY_VERSION)
    parser.add_argument("--show-ephemeral", action="store_true", help="print EphemeralEarlyPubKey and decoded public bytes for diagnosis")
    parser.add_argument("--probe", action="store_true", help="send a RakNet unconnected ping")
    parser.add_argument("--handshake", action="store_true", help="run standard RakNet connection negotiation")
    args = parser.parse_args(argv)

    cookie = read_cookie()
    if not cookie:
        print("ROBLOSECURITY is required", file=sys.stderr)
        return 2

    try:
        result = RobloxJoinClient(cookie).join(
            args.place_id,
            job_id=args.job_id,
            public_key_version=args.key_version,
        )
    except Exception as exc:
        print(f"web join FAILED: {exc}", file=sys.stderr)
        return 1

    print_join_summary(result)

    if args.show_ephemeral:
        encoded = str(result.join_script.get("EphemeralEarlyPubKey", ""))
        print("EphemeralEarlyPubKey (server response):")
        print(f"  {encoded}")
        try:
            raw = _b64decode(encoded)
            print(f"  decoded length: {len(raw)} bytes")
            print(f"  decoded hex: {raw.hex()}")
            if len(raw) >= 3:
                print(f"  first 3 bytes: {raw[:3].hex()}")
                print(f"  last 3 bytes:  {raw[-3:].hex()}")
        except Exception as exc:
            print(f"  base64 decode failed: {exc}")

    if not result.endpoints:
        return 0 if not (args.probe or args.handshake) else 2

    if args.probe:
        client = RakNetClient(*result.endpoints[0])
        try:
            data = client.probe()
            if data is None:
                print("UDP probe: no response")
                return 2
            print(
                f"UDP probe: response len={len(data)} first=0x{data[0]:02x}"
            )
        finally:
            client.close()

    if args.handshake:
        client = RakNetClient(*result.endpoints[0])
        try:
            hs = client.connect()
            print("RakNet handshake: OK")
            print(f"  server GUID: 0x{hs.server_guid:016x}")
            print(f"  MTU: {hs.mtu}")
            print(f"  encryption flag: {hs.use_encryption}")
        except RakNetError as exc:
            print(f"RakNet handshake: FAILED: {exc}", file=sys.stderr)
            return 2
        finally:
            client.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
