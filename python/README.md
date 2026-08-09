# rbxraknet

A small decoder for Roblox's RakNet-over-UDMUX wire protocol. Give it a capture and the key for
each direction and you get a decoded packet tree back. The decoder peels the outer framing
first, then the AEAD envelope, then the inner transport and replication grammar.

The only runtime dependency is [`cryptography`](https://pypi.org/project/cryptography/). No
memory forensics, no injection, nothing platform-specific.

## Scope and ethics

This is protocol reverse-engineering, for learning. It's a dissector for traffic you captured
from your own client, the same category as a Wireshark dissector. It reads a capture and that's
all it does. The full scope and ethics note is in the root [`README.md`](../README.md).

Session keys are per-connection and aren't shipped or recovered here. How a key gets pulled
(reading your own running client's memory in the same session) is left out on purpose, so this
stays a plain decoder with no key-grabbing code.

Where the key comes from is written up in [`../docs/WEB_JOIN_FLOW.md`](../docs/WEB_JOIN_FLOW.md).
Short version, it's an ephemeral X25519 ECDH output. The join handout from `gamejoin.roblox.com`
gives you both public keys (`RakNetEarlyPublicKey` and `EphemeralEarlyPubKey`) and a seed, but
never a private scalar or the symmetric key. So you can't pull the AEAD key out of captured
HTTPS, and passive decryption without opening the client won't work. The key lives in the
running client's memory as an ECDH output and never goes over the wire. Keys are per-session and
per-epoch, so a lifted key only decrypts its own session, and only its epoch if the session
re-keys.

## Install

```
pip install -r requirements.txt      # just: cryptography
```

## Use

Library:

```python
from rbxraknet import parse, AeadCodec, AES
from rbxraknet.inner import decode_inner

dg = parse(raw_udp_payload)                       # outer framing -> Datagram
plaintext, counter = AeadCodec(key, AES).decrypt(dg)
tree = decode_inner(plaintext)                    # transport + app-message tree
```

CLI (a capture is one hex UDP payload per line):

```
python -m rbxraknet.decode --capture cap.hex \
    --key-17 <32-byte hex>  --cipher-17 aes-256-gcm \
    --key-1f <32-byte hex>  --cipher-1f aes-256-gcm  --show 5
```

## The protocol

The outer datagram (`framing.py`):

| bytes | meaning |
|---|---|
| `[0]` | `0x01` UDMUX/RUPP flag |
| `[3]` | header length and direction id: `0x17` or `0x1f` |
| `[4:7]` | constant `01 11 02` |
| `[7:23]` | 16-byte epoch tag (rotates on re-key) |
| `[23:hlen]` | 8-byte mux_extra on `0x1f`, empty on `0x17` |
| `body[hlen:]` | `ciphertext || counter_hint(2, LE) || tag(16)` |

AEAD (`aead.py`) is AES-256-GCM, one key per direction, with `AAD = b""` and
`nonce = LE64(counter) || "mbeR"`. The counter starts at `LE64("UniqueNu")` =
`8452805105709313621` and ticks up by one per packet per direction. The 12-byte magic is
`"UniqueNumbeR"`. Only the low 16 bits ride the wire, so the full counter is recovered by trying
the handful of values that match that hint. ChaCha20-Poly1305 (Roblox format 0) works too, for
sessions that negotiate it.

The inner layer (`inner.py`, and see
[`../docs/INNER_PROTOCOL.md`](../docs/INNER_PROTOCOL.md) for the byte-level evidence). Once you
decrypt, the plaintext is a RakNet datagram, not an app packet. The first byte is a bitmask of
transport flags. DATA is any valid non-ACK flag (`0x80` through `0x83` show up) and ACK is `0xc0`
or `0xd0`. A DATA datagram is `[flags][datagramNumber:u24 LE]`, then one or more messages. Each
message is `[reliability][dataBitLength:u16 BE]` plus optional reliable, ordering, and split
headers, then the data. Under `0x83 ID_DATA` the app layer breaks into `0x03` PROP, `0x07` EVENT,
and physics and time blocks. Instances are 4-byte referents, names are length-prefixed ASCII.

### Coverage

Numbers here are from the decrypt capture, 77,575 payloads (`0x17`=37,170, `0x1f`=40,405). That's
a larger capture than the 16,797-payload one the framing invariants use.

| direction | AEAD decrypt | inner datagram tiling |
|---|---|---|
| `0x17` | 36522/37170 (98.3%) | 100.0% (2379 DATA + 1679 ACK, 0 unmodeled) |
| `0x1f` | 39598/40405 (98.0%) | 100.0% (1845 DATA + 1718 ACK, 0 unmodeled) |

Tiling means the transport model eats every byte of a DATA datagram with nothing left over, and
the reliable and ordering numbers come out as contiguous +1 counters. A wrong field offset
couldn't give you either. The full evidence chain is in
[`../docs/PROVENANCE.md`](../docs/PROVENANCE.md).

## Not decoded

- Property and event values. Roblox serializes these with no type tags, driven by a
  class/property schema that comes down in `ID_NEW_SCHEMA`. Without that schema the field widths
  are unknown, so the values stay raw.
- About 2% of packets belong to a second UDMUX backend. It's a different 8-byte mux tag on a
  low-traffic side channel that re-keys a lot to carry voice, telemetry, and mux-control, and it
  isn't the game server. Its per-connection keys were never in the single memory snapshot used to
  recover the main key, and ephemeral keys never travel on the wire, so nothing in the capture
  can decrypt them. The main game connection decodes 100%, meaning every packet under its key
  both decrypts and tiles. A literal 100% of a mixed capture would need keys captured live (a key
  log running through the whole session) or a session you drive yourself as an endpoint. Anything
  the grammar can't place falls back to `UNMODELED`.

## Files

`framing.py`, `aead.py`, `inner.py`, `decode.py` (the CLI), `__init__.py`, and
`requirements.txt`. Each module runs its own self-test with `python -m rbxraknet.<module>`.
