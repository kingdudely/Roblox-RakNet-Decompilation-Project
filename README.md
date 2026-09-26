# Roblox RakNet / SessionCrypto RE

Python-only working branch for reverse-engineering the current Roblox RakNet connection/session path.

Target build:
- Roblox Player: 9.4.260915.1d72b8c0
- Branch: python

This repository contains the Python tooling and the protocol notes that are currently supported by the code. The reverse-engineering conclusions below are based on IDA analysis of the target client, not on assumptions about vanilla RakNet.

## Current state

The web join stage works:

1. Obtain an authentication ticket.
2. Call GameJoin.
3. Read `UdmuxEndpoints`.
4. Generate a local X25519 key pair.
5. Decode `EphemeralEarlyPubKey`.
6. Compute the join-stage X25519 shared secret.
7. Compute the existing SHA-512 join transcript used by the Python bring-up code.

The UDP connection path has been corrected from vanilla RakNet to Roblox's current offline handshake.

The current packet IDs are:

| ID | Name |
|---|---|
| `0x7B` | RbxOpenRequest1 |
| `0x7E` | RbxOpenReply1 |
| `0x78` | RbxOpenRequest2 |
| `0x7D` | RbxOpenReply2 |

The vanilla sequence beginning with `0x01` UNCONNECTED_PING and `0x05` OPEN_CONNECTION_REQUEST_1 is not the current Roblox path being implemented here.

## RbxOpenRequest1

IDA shows `sub_2897560` constructing:

```text
byte 0       0x7B
bytes 1..16  00 FF FF 00 FE FE FE FE FD FD FD FD 12 34 56 78
byte 17      0x05
byte 18      Rupp opt-in
padding      zeroes
```

The magic is stored in `xmmword_64E2A50`.

The real client sets the Rupp opt-in byte to `1` in `sub_2897560`.

`sub_28979D0` also contains an explicit `0` path that omits the Rupp response header, but the current Python implementation matches the canonical client and sends `1`.

The constructor is called with `MTU - 40`; for the current default MTU of 1492 this makes the UDP payload 1452 bytes.

## RbxOpenReply1

The dispatcher identifies `0x7E` as RbxOpenReply1 and the client parser is `sub_2897F00`.

The reply is the next packet required before constructing Request2. Its complete field semantics are intentionally not guessed in the Python client yet; the bring-up code records the raw reply.

## Request2 encryption

Request2 is not vanilla RakNet OpenConnectionRequest2.

The client constructor is `sub_2898470`.

It first creates an offline/Rupp prefix with `sub_289FC80`. That prefix is the clear authenticated-data region. We do not need to understand the Rupp semantics to reason about the AEAD layout, and the Python branch currently treats that portion as an unresolved serialization task.

The server-side parser `sub_28994F0` confirms that the authenticated-data length is read before decryption and rejects an AAD length below `0x35`.

The encrypted body begins with the fields written by `sub_2898470`, including:

```text
0x78
RakNet magic
0x03
0x00
two 16-bit fields
32-byte public key
additional negotiated/session fields
```

The exact bit-level serialization of every later field is still being implemented from the IDA evidence.

## SessionCrypto AEAD

The current SessionCrypto cipher path is ChaCha20-Poly1305.

This is directly established by:

- `sub_28C4E90` constructing the ChaCha20 state with `"expand 32-byte k"` and counter 0.
- `sub_28C5070` constructing the same state and encrypting with counter 1.
- `sub_28C5A80` applying the Poly1305 26-bit limb/clamping masks.
- `sub_28C5640` implementing the Poly1305 multiplication/reduction.
- `sub_28C5440` finalizing the 16-byte Poly1305 tag.

The AEAD layout is:

```text
AAD / offline-Rupp prefix
encrypted Request2 body
12-byte nonce
16-byte Poly1305 tag
```

The decryptor `sub_28BA1D0` subtracts exactly 28 bytes from the packet size. `sub_57DF050` receives the ciphertext, AAD length, nonce area and tag area.

The Poly1305 input is:

```text
AAD
zero padding to 16
ciphertext
zero padding to 16
LE64(AAD length)
LE64(ciphertext length)
```

## Nonce

`sub_28BA070` writes the 12-byte nonce as:

```text
LE64(counter + 0x754E657571696E55)
6D 62 65 52
```

The constants decode to:

```text
"UniqueNu" + "mbeR"
```

so the nonce is:

```text
LE64(UniqueNumber-derived counter) || b"mbeR"
```

The exact initial value and counter lifetime belong to SessionCrypto state and are still being traced.

## SessionCrypto key derivation

`sub_28DD1B0` allocates a 352-byte SessionCrypto workspace.

The first fields are:

| Offset | Size | Current interpretation |
|---|---:|---|
| `+0x00` | 32 | local X25519 public key |
| `+0x20` | 32 | local X25519 private/scalar |
| `+0x40` | 32 | key-exchange input |
| `+0x60` | 32 | key-exchange input |
| `+0x80` | 32 | second key-exchange input |
| `+0xA0` | 32 | second key-exchange input |
| `+0xC0` | 32 | derived key 1 |
| `+0xE0` | 32 | derived key 2 |
| `+0x100` | 32 | derived key 3 |
| `+0x120` | 32 | derived key 4 |

`sub_28D0EB0` performs the X25519 scalar clamping and public-key generation.

`sub_28C0E30` performs an X25519 operation followed by SHA-512 based derivation and splits its 64-byte result into two 32-byte outputs. The exact argument-to-field interpretation is still being pinned down; the Python branch does not label the resulting digest halves as final SessionCrypto keys.

`sub_28BA4D0` supplies four 32-byte key-exchange values. Its `a2 == 0` path uses built-in values; the nonzero path loads dynamically supplied values. The current Request2 constructor starts with its key-exchange flag at zero, so the Python bring-up does not enable the dynamic path.

## Rupp

Rupp is deliberately not being fully implemented yet.

There are two distinct cases:

- Request1 Rupp opt-in can be disabled by sending byte 18 as `0`.
- Request2 still creates an offline/Rupp-derived authenticated-data prefix through `sub_289FC80`.

The first case is disabled in the Python client. The second is currently treated as an opaque AAD serialization problem rather than expanding the implementation with token semantics that are not yet required.

## Reply2

`sub_289BDF0` is the client-side RbxOpenReply2 parser.

`sub_289B300` is the server-side RbxOpenReply2 constructor/sender reached after successful Request2 processing.

The full Reply2 field model is not yet implemented in Python.

## Python layout

```text
python/
  rbxraknet/
    __init__.py
    aead.py       # existing UDMUX capture AEAD decoder
    client.py     # GameJoin + current offline handshake bring-up
    decode.py     # capture decoder CLI
    framing.py    # outer UDMUX framing
    inner.py      # inner RakNet grammar
    raknet.py     # current Roblox offline-handshake transport
  tests/
    test_client.py
  requirements.txt
```

The existing `aead.py`/capture-decoder code is separate from the SessionCrypto preauth path described above. It is retained because it handles the repository's previously decoded UDMUX gameplay captures.

## Install

```bash
cd python
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Bring-up

Set `ROBLOSECURITY`, then:

```bash
python -m rbxraknet.client --place-id YOUR_PLACE_ID --handshake
```

The current handshake command performs GameJoin, sends RbxOpenRequest1 with Rupp opt-in disabled, and waits for RbxOpenReply1. It does not pretend that Request2 or the full Roblox session is implemented.

For packet tracing:

```bash
python -m rbxraknet.client --place-id YOUR_PLACE_ID --handshake --udp-trace
```

## Status

Implemented and supported by IDA evidence:

- GameJoin endpoint discovery.
- Local X25519 generation.
- RbxOpenRequest1 `0x7B`.
- Request1 magic and protocol `5`.
- Request1 Rupp opt-in disable.
- RbxOpenReply1 detection `0x7E`.
- Request2/Reply2 packet IDs.
- ChaCha20-Poly1305 primitive.
- 12-byte SessionCrypto nonce construction.
- 28-byte nonce+tag trailer.
- SHA-512/X25519 SessionCrypto derivation structure.
- SessionCrypto workspace layout at the currently identified fields.

Not yet implemented:

- Exact offline-Rupp AAD serialization in Python.
- Complete Request2 field serializer.
- Exact SessionCrypto key-field interpretation after the second-stage exchange.
- Exact initial UniqueNumber counter state.
- RbxOpenReply2 serializer/parser in Python.
- Post-Reply2 RakNet reliability/session traffic for the live client.

The branch intentionally stops at the last point that can be represented honestly from the current reverse-engineering evidence.
