# rbxraknet

Decodes Roblox's RakNet-over-UDMUX game traffic, from the outer datagram framing through the
AEAD envelope (cipher, keys, nonce) down to the inner RakNet reliability and replication
grammar. There are also notes on the web join flow and the client-side session/token setup.

Everything works off a capture from your own client, the same idea as a Wireshark dissector. It
doesn't connect to Roblox, doesn't log in, and isn't a game client or a cheat. Session keys are
per-connection and aren't included. Don't use any of this to break Roblox's ToS.

## What's here

| Path | What |
|---|---|
| `python/rbxraknet/` | The reference decoder. Framing, AEAD, inner grammar. Only needs `cryptography`, and has a CLI. |
| `cpp/decoder/` | The same decoder as a C++/OpenSSL library, with CMake and unit tests. |
| `cpp/headless_join.cpp` | Sketch of the whole flow from web join to ECDH to decrypt. The KDF and packet-token stages remain incomplete. |
| `docs/WEB_JOIN_FLOW.md` | The HTTPS join flow, the X25519 exchange, the KDF findings, and the Rupp token path. |
| `docs/INNER_PROTOCOL.md` | The inner RakNet grammar, with the byte-level evidence. |
| `docs/PROVENANCE.md` | What's measured vs inferred, including the latest IDA reverse-engineering findings. |

## Quick start (Python)

```
cd python
pip install -r requirements.txt          # just: cryptography
python -m rbxraknet.decode --capture cap.hex --key-17 <hex> --key-1f <hex>
```

`cap.hex` is one hex UDP payload per line. Keys are per-direction, 32-byte AES-256-GCM. The
library API, the wire layout, and test coverage are in `python/README.md`.

## Reverse-engineering status

The current IDA work targets Roblox client build `9.4.260915.1d72b8c0`.

The session-crypto path is now substantially identified:

- `sub_28DD1B0` creates a 352-byte crypto workspace and generates the local X25519 key pair.
- `sub_28D0EB0` clamps the 32-byte scalar and performs the X25519-style public-key ladder.
- `sub_28B9FD0` receives the 32-byte peer public key and calls `sub_28C0B20`.
- `sub_28C0B20` performs the X25519 ECDH operation and then runs a SHA-512 based derivation over the shared secret plus the local and peer public keys. The exact downstream interpretation/splitting of its 64-byte digest is still being traced.
- `sub_28BA1D0` / `sub_28DD510` feed the resulting crypto state into the AES-GCM packet path.

The Rupp packet-token path is also mapped farther than the original public notes:

```
joinScript TokenValue
    -> sub_11D5AA0
    -> 16-byte value
    -> sub_2277EA0
    -> Rupp token state

Rupp send path
    -> sub_2275560
    -> sub_2275400
    -> object at a1+0x40
    -> vtable + 0x10
    -> 16-byte generated token
    -> sub_2275C70
    -> Rupp header
```

The client exposes configuration metadata named `SetTokenValue`, `SetTokenGenAlgo`, and
`SetTokenPepper`. Their reflection-registration wrappers are known, but the concrete token
generator implementation that consumes the configured values is still being located.

## Status

Verified against a live session. The outer framing round-trips losslessly across 16,797
payloads. The AEAD is AES-256-GCM in both directions, the nonce is `LE64(counter) || "mbeR"`,
and the AAD is empty. The inner grammar tiles 100% in both directions. Property and event values
aren't decoded yet. They need the class schema that comes down in `ID_NEW_SCHEMA`.

The remaining work for a self-contained headless transport is concentrated in two areas:

1. Finish the client-side KDF, including the exact output/key split and epoch rekey derivation.
2. Finish the Rupp packet-token generator, including how `TokenGenAlgorithm` and `PepperId`
   feed the 16-byte token.

See `docs/PROVENANCE.md` and `docs/WEB_JOIN_FLOW.md` for the build-specific evidence.

## License

MIT. See `LICENSE`.
