# Provenance

This file backs up every protocol claim in the repo, split into what's measured off the wire and
what's still inferred. The session keys are redacted. They're per-session and ephemeral, described
in the last section, and they decrypt nothing after the fact anyway.

## Outer framing (measured)

Checked against a 16,797-payload capture of one live session (RakNet server 128.116.53.33, place
7041939546). The framing is re-asserted on every run of the C++ `test_frame` (204,617 assertions)
and the Python `framing` self-test, so it is not a one-time check.

- Every payload has the shape `outer_header || ciphertext || counter_hint(2,LE) || tag(16)`. All
  16,797 parse with zero failures.
- `byte[0]=0x01`, `byte[1..2]=0`, and `byte[3]` is both the header length and the direction id,
  taking only the values `0x17` or `0x1f`. `byte[4..6]=01 11 02` is constant. `byte[7..22]` is a
  16-byte epoch tag that rotates through 25 distinct recurring values.
- `0x1f` carries an 8-byte mux field at `byte[23..30]`. `0x17` does not, since its header is
  exactly 23 bytes and leaves no room for one.
- `counter_hint` steps +1 per packet per direction. Restart the count at each epoch boundary and
  same-epoch |delta|<=1 jumps to 99.9%. The leftover on `0x17` is retransmission. 88.9% of `0x17`
  is re-sent, each block up to roughly 9x, and every larger delta lands on a counter that repeats
  within its epoch.
- `serialize(parse(p)) == p` byte-for-byte for all 16,797 payloads, so the framing model is
  lossless. A dropped or mismodeled field could not come back on serialize.

## AEAD (measured, keys redacted)

Both directions use AES-256-GCM with empty AAD and the nonce `= LE64(counter) || "mbeR"`. The
counter starts at `LE64("UniqueNu") = 8452805105709313621` and increments per packet per
direction. The 12-byte magic spells `UniqueNumbeR`. Only the low 16 bits ride the wire.

The per-direction keys were recovered read-only from a same-session memory snapshot of the
client, with no hooking and no anti-tamper interaction. The `0x17` key showed up as a resident
AES-256 key schedule, and the `0x1f` key was next to it, stored raw, 32 bytes. The AEAD and
inner-grammar work used a larger capture than the framing one above, 77,575 payloads
(`0x17`=37,170, `0x1f`=40,405). Under those keys it decrypts with authenticated GCM tags,
36,522/37,170 on `0x17` and 39,598/40,405 on `0x1f`. The remaining roughly 2% is a second UDMUX
backend, a low-traffic side channel with a distinct mux tag that re-keys often. Its ephemeral keys
were never in the snapshot, which is why that 2% doesn't decrypt.

## Inner grammar (measured)

Once you decrypt, the plaintext is a RakNet datagram, not an application packet. The transport,
reliability, and split model tiles 100% of the distinct DATA datagrams with zero leftover bytes
(`0x17` has 2,379 DATA and 1,679 ACK, `0x1f` has 1,845 DATA and 1,718 ACK), and the reliable and
ordering numbers it pulls out form contiguous +1 counters, which a wrong field offset couldn't
produce. The app id `0x83 ID_DATA` and its block types (PROP, EVENT, physics, time) are confirmed
by histogram. Property and event values aren't decoded. Roblox serializes them without type tags,
driven by a class and property schema that comes down in `ID_NEW_SCHEMA`. Full byte evidence is
in `INNER_PROTOCOL.md`.

## Key origin (inferred)

The AEAD key is an ephemeral X25519 ECDH output. The web join handout gives you both public
halves and a seed, but never a private scalar or the symmetric key. So passive decryption is out,
and so is any decryption that doesn't open the client. That's why the keys were recovered by
memory forensics on the client instead. The full flow and where each piece comes from are in
`WEB_JOIN_FLOW.md`.

## Not reversed

- The KDF that turns the ECDH shared secret into the AEAD key, and the per-epoch rekey.
- The per-packet anti-tamper token (`TokenValue`, `TokenGenAlgorithm`, `PepperId`).

Both live in the client binary, and they're the last two pieces between this and a working
headless session. See `../cpp/headless_join.cpp`.
