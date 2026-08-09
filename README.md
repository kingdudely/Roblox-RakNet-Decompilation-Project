# rbxraknet

Decodes Roblox's RakNet-over-UDMUX game traffic, from the outer datagram framing through the
AEAD envelope (cipher, keys, nonce) down to the inner RakNet reliability and replication
grammar. There are also notes on the web join flow and where the session key comes from.

Everything works off a capture from your own client, the same idea as a Wireshark dissector. It
doesn't connect to Roblox, doesn't log in, and isn't a game client or a cheat. Session keys are
per-connection and aren't included. Don't use any of this to break Roblox's ToS.

## What's here

| Path | What |
|---|---|
| `python/rbxraknet/` | The reference decoder. Framing, AEAD, inner grammar. Only needs `cryptography`, and has a CLI. |
| `cpp/decoder/` | The same decoder as a C++/OpenSSL library, with CMake and unit tests. |
| `cpp/headless_join.cpp` | Sketch of the whole flow from web join to ECDH to decrypt. The two unfinished bits are marked. |
| `docs/WEB_JOIN_FLOW.md` | The HTTPS join flow, and where the AEAD key comes from (ephemeral X25519 ECDH). |
| `docs/INNER_PROTOCOL.md` | The inner RakNet grammar, with the byte-level evidence. |
| `docs/PROVENANCE.md` | What's measured vs inferred, claim by claim. |

## Quick start (Python)

```
cd python
pip install -r requirements.txt          # just: cryptography
python -m rbxraknet.decode --capture cap.hex --key-17 <hex> --key-1f <hex>
```

`cap.hex` is one hex UDP payload per line. Keys are per-direction, 32-byte AES-256-GCM. The
library API, the wire layout, and test coverage are in `python/README.md`.

## Status

Verified against a live session. The outer framing round-trips losslessly across 16,797
payloads. The AEAD is AES-256-GCM in both directions, the nonce is `LE64(counter) || "mbeR"`,
and the AAD is empty. The inner grammar tiles 100% in both directions. Property and event values
aren't decoded yet. They need the class schema that comes down in `ID_NEW_SCHEMA`.

Two pieces are written up but not reversed, and they're the only thing between this and a
headless session. One is the KDF that turns the ECDH shared secret into the AEAD key. The other
is the per-packet anti-tamper token. Both live inside the client binary. See
`cpp/headless_join.cpp` for where they'd go.

## License

MIT. See `LICENSE`.
