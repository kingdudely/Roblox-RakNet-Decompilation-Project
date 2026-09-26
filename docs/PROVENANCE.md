# Provenance

This file backs up every protocol claim in the repo, split into what's measured off the wire,
what is confirmed by static reversing, and what's still inferred. The session keys are redacted.
They're per-session and ephemeral.

## Outer framing (measured)

Checked against a 16,797-payload capture of one live session (RakNet server 128.116.53.33, place
7041939546). The framing is re-asserted on every run of the C++ `test_frame` (204,617 assertions)
and the Python `framing` self-test, so it is not a one-time check.

- Every payload has the shape `outer_header || ciphertext || counter_hint(2,LE) || tag(16)`.
- `byte[0]=0x01`, `byte[1..2]=0`, and `byte[3]` is both the header length and the direction id,
  taking only `0x17` or `0x1f`.
- `byte[4..6]=01 11 02` is constant and `byte[7..22]` is a 16-byte epoch tag.
- `0x1f` carries an 8-byte mux field at `byte[23..30]`; `0x17` does not.
- `counter_hint` is the low 16 bits of the per-direction nonce counter.
- `serialize(parse(p)) == p` byte-for-byte for all 16,797 tested payloads.

## AEAD (measured)

Both directions use AES-256-GCM with empty AAD and nonce `LE64(counter) || "mbeR"`.
The counter starts at `LE64("UniqueNu")` and increments per packet per direction.

A larger 77,575-payload capture was decrypted using keys recovered read-only from a same-session
client memory snapshot. The remaining roughly 2% belonged to a second UDMUX backend whose
ephemeral keys were not present in that snapshot.

## Inner grammar (measured)

Once decrypted, the plaintext is a RakNet datagram. The transport, reliability, and split model
tiles 100% of the distinct DATA datagrams with zero leftover bytes in the tested corpus. The app
id `0x83 ID_DATA` and block types (PROP, EVENT, physics, time) are confirmed by histogram.

## Static reverse-engineering: session crypto (confirmed)

Target build: Roblox client `9.4.260915.1d72b8c0`, x86-64.

### SessionCrypto workspace

`sub_28DD1B0(a1)` allocates a 352-byte workspace and initializes the key material areas:

- `+0x00..0x1F`: local public key
- `+0x20..0x3F`: local private scalar
- `+0x40..0x5F`: peer/server public key
- `+0xC0..0xDF`: SHA/KDF state/scratch
- `+0xE0..0xFF`: derived 32-byte/output area

The constructor path starts from `sub_28853C0`, which initializes the SessionCrypto/RakPeerCrypto
object and the `"UniqueNu"` nonce base.

### X25519

`off_7D21958 -> sub_28D0EB0` is the scalar/public-key operation. The scalar is clamped by
clearing the low three bits, clearing the top bit, and setting the next-high bit. The body performs
a Montgomery-ladder style 255-bit calculation.

`sub_28B9FD0` then copies the 32-byte peer public key into the workspace and calls:

```
sub_28C0B20(
    output = buffer + 0xE0,
    scratch = buffer + 0xC0,
    local_public = buffer + 0x00,
    local_private = buffer + 0x20,
    peer_public = peer_key
)
```

The X25519 backend is reached through `off_7D6BF78 -> off_7D21950 -> sub_28D06F0`.

### SHA-512-based derivation

`sub_28C0B20` first computes the X25519 shared secret with the local private scalar and the
peer public key. It then initializes the SHA-512 state with the standard eight SHA-512 IV words,
updates the hash with:

1. the 32-byte ECDH shared secret,
2. the 32-byte local public key,
3. the 32-byte peer public key,

and finalizes through `sub_28CF3E0`.

This confirms a SHA-512-based post-ECDH derivation over the shared secret and both public keys.
The exact interpretation/splitting of the resulting digest into packet keys, and the epoch
rekey operation, are still being traced. No undocumented label is asserted here.

## Static reverse-engineering: Rupp packet token (confirmed path)

The join/config code reads `TokenValue`, `NetStackTokenValue`, `NetStackPort`, and `UdmuxToken`.
For `TokenValue`, the relevant chain is:

```
"TokenValue"
    -> sub_59BD480(...)
    -> sub_7E39A0(...)
    -> sub_11D5AA0(...)
    -> 16-byte result
    -> sub_7C99C0(...)
    -> sub_2277EA0(...)
```

`sub_2277EA0` wraps a 16-byte value as a present/valid token state. It does not generate the
token itself.

The runtime generation path is:

```
sub_2275560(...)
    -> sub_2275400(...)
    -> v4 = *(a1 + 0x40)
    -> call *(vtable(v4) + 0x10)(v4, &output)
    -> 16-byte token
    -> sub_2275C70(...)
```

`sub_2275400` logs `"[DFLog::RuppTokenClientLog2] Generating new Rupp token."` immediately
before the virtual call. The output is required to be exactly 16 bytes. `sub_2275C70` rejects
anything other than a 16-byte value and stores it into the Rupp token state used for the outgoing
header.

### Token configuration metadata

The client contains these setter names:

- `SetTokenValue`
- `SetTokenGenAlgo`
- `SetTokenPepper`

Their registration wrappers ultimately pass the following backing storage/descriptors into the
generic `sub_497BC40` registration routine:

- `SetTokenValue` -> `qword_7DB7010`
- `SetTokenGenAlgo` -> `unk_85C9DD0`
- `SetTokenPepper` -> `unk_85C9DE8`

Those are configuration/reflection registrations, not the generator implementation itself.

The concrete virtual function at `vtable + 0x10` for the object stored at `a1+0x40` has not yet
been identified. That is the current narrow target for completing the packet-token reversal.

## Not reversed / still inferred

- The exact split of the SHA-512-derived data into transmit/receive AEAD keys.
- The epoch/rekey derivation and the role of the 16-byte epoch tag in that derivation.
- The concrete Rupp token generator behind `vtable + 0x10`.
- How `TokenGenAlgorithm` and `PepperId` transform/configure the 16-byte generated token.
- Application-level property/event schemas beyond the transport grammar.

These are the remaining client-side pieces between the current reverse-engineering state and a
fully self-contained headless transport.

## Sources

Roblox GameJoin, auth, and join-flow specs and field schemas:

- Roblox GameJoin Api v1 Swagger (tracked): https://github.com/Paficent/Roblox-Api-Tracker/blob/main/gamejoin/v1.json
- Roblox-Client-Tracker, decompiled `JoinInformation` OpenAPI model: https://github.com/MaximumADHD/Roblox-Client-Tracker
- `synpixel/roblox-api-types` gamejoin type defs: https://github.com/synpixel/roblox-api-types/blob/main/types/gamejoin.luau
- `AlroviOfficial/RoZod` gamejoin v1 endpoints: https://github.com/AlroviOfficial/RoZod/blob/main/src/endpoints/gamejoinv1.ts
- `NoTwistedHere/Roblox-Apis`: https://github.com/NoTwistedHere/Roblox-Apis/tree/main/Documentations
- ROBLOX Reverse-Engineering site: https://docs.robloxreverseengineering.net/

RakNet AEAD / nonce lineage:

- `sajicooltoday/openwrt-rbxraknet`: https://github.com/sajicooltoday/openwrt-rbxraknet

Cryptographic background:

- X25519: https://cryptography.io/en/stable/hazmat/primitives/asymmetric/x25519/
- RFC 8418: https://datatracker.ietf.org/doc/html/rfc8418
