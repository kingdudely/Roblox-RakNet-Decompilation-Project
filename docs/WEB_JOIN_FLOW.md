# Roblox web join flow and the RakNet AEAD session key

The RakNet transport encrypts each direction with a 32-byte key. The HTTPS join response supplies
the public-key material and seed needed by the client-side setup, but not the private scalar or
raw session key.

This document now includes static-reversing results from Roblox client build
`9.4.260915.1d72b8c0`. Reverse-engineered claims are marked explicitly; they should not be
read as claims about every Roblox build.

## Ordered HTTPS join flow

The relevant flow is:

1. Hold an authenticated web session.
2. Obtain an X-CSRF token for state-changing requests.
3. Obtain the short-lived authentication ticket.
4. Call the GameJoin endpoint and receive `joinScript`.
5. Use the joinScript's connection, ticket, public-key, seed, and token fields to initialize the
   transport.
6. Open RakNet over UDMUX and continue with the encrypted session.

The joinScript contains the following crypto-relevant fields:

- `ClientPublicKeyData`
- `EphemeralEarlyPubKey`
- `RandomSeed1`
- `TokenValue`
- `TokenGenAlgorithm`
- `PepperId`

The first three are involved in session setup; the last three belong to the separate Rupp
packet-token path.

## Client-side X25519 setup (static reverse)

The client creates a 32-byte local X25519 key pair in the SessionCrypto workspace.

The relevant chain is:

```
sub_28DD1B1
    -> local public/private key workspace
    -> sub_28D0EB0
    -> X25519-style public-key calculation

sub_28B9FD0
    -> copies peer public key
    -> sub_28C0B20
```

The call inside `sub_28C0B20` reaches the X25519 backend through:

```
off_7D6BF78
    -> off_7D21950
    -> sub_28D06F0
```

The arguments to `sub_28C0B20` are:

```
output        = buffer + 0xE0
scratch       = buffer + 0xC0
local_public  = buffer + 0x00
local_private = buffer + 0x20
peer_public   = join-script peer key
```

## KDF finding: SHA-512 after ECDH

The ECDH shared secret is not used directly as the AEAD key.

Static analysis of `sub_28C0B20` shows:

1. X25519 computes the 32-byte shared secret.
2. A SHA-512 context is initialized with the standard SHA-512 IV.
3. The hash input is updated with the 32-byte shared secret.
4. The local 32-byte public key is added.
5. The peer 32-byte public key is added.
6. SHA-512 finalization produces the derived digest/output.

Therefore the current build's post-ECDH construction is confirmed to be SHA-512 based on:

```
SHA512(
    X25519(local_private, peer_public)
    || local_public
    || peer_public
)
```

The exact downstream mapping from the 64-byte digest to the active AEAD keys is still under
investigation, as is the per-epoch rekey derivation. The current evidence does **not** justify
inventing a label, HKDF info string, or epoch formula.

## Rupp packet-token path

The join/configuration code reads `TokenValue` and related Rupp fields.

For `TokenValue`:

```
TokenValue
  -> sub_11D5AA0
  -> 16-byte result
  -> sub_2277EA0
  -> stored Rupp token value/state
```

The runtime packet path is:

```
sub_2275560
  -> sub_2275400
  -> object = *(a1 + 0x40)
  -> object.vtable + 0x10
  -> generate 16-byte token
  -> sub_2275C70
  -> store/update Rupp token header
```

`sub_2275400` contains the log message:

```
[DFLog::RuppTokenClientLog2] Generating new Rupp token.
```

and then invokes the virtual method at offset `0x10` on the object at `a1+0x40`.

`sub_2275C70` validates that the supplied token is exactly 16 bytes and updates the current
Rupp token state. `sub_2275560` handles regeneration timing and then serializes the resulting
Rupp material into outgoing data.

## Token configuration names

The binary contains three related setter names:

```
SetTokenValue
SetTokenGenAlgo
SetTokenPepper
```

The generic reflection registration path is `sub_497BC40`. The backing descriptors discovered
for the current build are:

```
SetTokenValue   -> qword_7DB7010
SetTokenGenAlgo -> unk_85C9DD0
SetTokenPepper  -> unk_85C9DE8
```

These registrations establish that the three values exist as runtime configuration, but they do
not themselves implement the generator.

The current reverse-engineering target is therefore the concrete implementation behind:

```
(*(vtable_of_object_at_a1_plus_0x40 + 0x10))(object, output)
```

That function should explain how the configured token value, generation algorithm, and pepper are
combined into the 16-byte packet token.

## What is still needed for a self-contained headless transport

The transport is much closer than the original notes suggested, but two protocol details remain:

- exact AEAD key extraction from the SHA-512 post-ECDH output, including direction/key ordering;
- epoch rekey derivation;
- concrete Rupp token generator implementation and its use of `TokenGenAlgorithm` and
  `PepperId`.

The public project originally treated both the KDF and packet token as completely unreversed.
The current build-specific reversing narrows that substantially, but neither remaining detail
should be considered solved until the concrete binary path has been traced.

## Sources

- GameJoin Swagger: https://github.com/Paficent/Roblox-Api-Tracker/blob/main/gamejoin/v1.json
- Roblox client tracker: https://github.com/MaximumADHD/Roblox-Client-Tracker
- This project's headless join sketch: `../cpp/headless_join.cpp`
- This project's measured/inferred provenance: `PROVENANCE.md`
- X25519 background: https://cryptography.io/en/stable/hazmat/primitives/asymmetric/x25519/
