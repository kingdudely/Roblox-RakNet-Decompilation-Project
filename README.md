# Roblox RakNet / SessionCrypto RE

Python working branch for reverse-engineering the current Roblox RakNet connection/session path.

Target build:
- Roblox Player: 9.4.260915.1d72b8c0
- Branch: python

## Current state

The web join stage works:
1. Obtain an authentication ticket.
2. Call GameJoin.
3. Read UdmuxEndpoints.
4. Generate a local X25519 key pair.
5. Decode EphemeralEarlyPubKey.
6. Compute the join-stage X25519 shared secret.
7. Compute the confirmed SHA-512 post-ECDH digest.

The UDP connection path currently implements the first Roblox-specific offline packet:
- 0x7B RbxOpenRequest1
- 0x7E RbxOpenReply1
- 0x78 RbxOpenRequest2
- 0x7D RbxOpenReply2

The Python branch intentionally stops before emitting Request2 because the exact AAD/Rupp prefix and
all Request2 fields have not yet been serialized from the Android target.

## Proven SessionCrypto evidence

For build 9.4.260915.1d72b8c0, static reversing establishes:

    shared = X25519(local_private, peer_public)
    digest = SHA512(shared || local_public || peer_public)

The client stores local public at SessionCrypto workspace +0x00, private scalar at +0x20, peer key at
+0x40, KDF scratch at +0xC0, and the 64-byte post-ECDH output at +0xE0.

The Python branch exposes that derivation in rbxraknet.sessioncrypto, but deliberately does not label
either 32-byte digest half as a TX/RX key. That split remains an IDA target.

The confirmed nonce is:
    LE64(counter) || b'mbeR'

with initial counter LE64('UniqueNu'), so the initial 12-byte nonce spells UniqueNumbeR.

## What remains

- Exact offline/Rupp AAD serialization from sub_289FC80.
- Complete Request2 field serializer from sub_2898470.
- Exact TX/RX key selection from the 64-byte SHA-512 result.
- Epoch/rekey derivation.
- RbxOpenReply2 parser/serializer.
- Post-Reply2 RakNet reliability/session traffic.
- Concrete Rupp token generator behind the virtual call at vtable + 0x10.

See docs/IDA_SESSIONCRYPTO.md for exact IDA targets and the bytes/arguments to record.

## Python layout

python/
  rbxraknet/
    aead.py
    client.py
    decode.py
    framing.py
    inner.py
    raknet.py
    sessioncrypto.py
  tests/
    test_client.py
    test_sessioncrypto.py

## Install

    cd python
    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -r requirements.txt

## Bring-up

Set ROBLOSECURITY, then:

    python -m rbxraknet.client --place-id YOUR_PLACE_ID --handshake

The current command performs GameJoin, sends RbxOpenRequest1 with the canonical client Rupp opt-in
byte 0x01, and waits for RbxOpenReply1. It does not pretend Request2 or the full Roblox session is
implemented.

For packet tracing:

    python -m rbxraknet.client --place-id YOUR_PLACE_ID --handshake --udp-trace

## Status discipline

The branch distinguishes measured/static-reversed facts tied to a specific Roblox build, protocol
structures that are still unresolved, and implementation guesses.
Unresolved fields are not filled with vanilla RakNet assumptions. Android x86-64 addresses must be
reversed independently from Windows addresses even when the semantic function is the same.
