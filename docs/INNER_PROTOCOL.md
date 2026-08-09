# Inner (decrypted) Roblox-RakNet packet format, direction 0x17

This is the packet layout on the inside, after decryption. Direction 0x17 only.

The layouts here come from 4,058 distinct decrypted plaintexts, pulled out of 37,170 dir-0x17
datagrams in a 77,575-payload capture. That's the same larger capture the AEAD numbers use, not
the 16,797-payload framing capture. 88.9% of those were retransmits, so most of the raw volume is
duplicates. They were decrypted with the recovered AES-256-GCM key. The decoder and its
self-check live in `rbxraknet/inner.py`.

Every layout below is measured against that corpus, with the evidence sitting right next to it.
A field that's a good guess and not actually confirmed is marked as such. The reference model
this started from (`openwrt-rbxraknet`) had stale inner ids, so where the bytes disagree with it,
the bytes win.

RakNet is a bit-oriented BitStream protocol, so in theory fields don't have to land on byte
boundaries. This Roblox build byte-aligns every field parsed here though. The model
tiles all 2,379 DATA datagrams on exact byte boundaries with zero leftover bits, so the decoder
works in bytes, not bits. Endianness is mixed and matches the wire. The self-check asserts both
directions. Counters are little-endian, while `dataBitLength` and the split header are big-endian.

## Layer 0: the plaintext is a RakNet datagram, not an app packet

Once you decrypt a packet you get a RakNet datagram, not a Roblox message: the first byte is
datagram flags, not a message id. The leading-byte histogram over all 4,058 distinct plaintexts:

| flags | count | % | meaning |
|------:|------:|--:|---|
| `0x80` | 1844 | 45.4% | DATA datagram (plain) |
| `0xd0` | 1679 | 41.4% | ACK datagram |
| `0x82` |  535 | 13.2% | DATA datagram (one extra transport flag bit `0x02`; structurally identical to `0x80`) |

`0x80` and `0x82` are both DATA and parse the exact same way (dgram number, reliability, length,
data), and they tile exactly. The extra `0x02` bit on `0x82` is unexplained. It looks like
RakNet's `isContinuousSend` and makes no structural difference. `0xd0` is ACK. Its payload is
datagram-number ranges and never app data, covered in Layer 3.

The candidate ids `0x81/0x83/0x85/0x97/0x98/0x9B` never show up as leading bytes. `0x83` is an
inner app id, but it lives two layers down in Layer 4.

## Layer 1: DATA datagram header

```
off  size  field            enc      value
0    1     flags            u8       0x80 / 0x82
1    3     datagramNumber   u24 LE   increments ~+1 per datagram
4    ...   message[0..]              one or more concatenated messages (Layer 2)
```

Evidence. `datagramNumber` at [1:4] LE climbs monotonically across capture order (for example
161926, 161929, 161930). 870 of the 2,379 DATA datagrams carry more than one message, and the
model tiles every one of them exactly. The Layer 2 boundaries land with 0 leftover bytes, which
`rbxraknet.inner._selftest` checks.

## Layer 2: per-message reliability header

Each message starts with a reliability byte. The top 3 bits are the RakNet reliability enum, and
bit 4 is `hasSplitPacket`.

```
+0   1   reliability byte   bits[7:5]=reliability, bit[4]=hasSplitPacket
+1   2   dataBitLength      u16 BE      length of message data in BITS
--- present only if reliability is RELIABLE (2,3,4): ---
     3   reliableMessageNumber   u24 LE
--- present only if ORDERED/SEQUENCED (1,3,4): ---
     3   orderingIndex           u24 LE
     1   orderingChannel         u8
--- present only if hasSplitPacket (bit4 set): ---
     10  split header (Layer 2b)
---
     N   data                ceil(dataBitLength/8) bytes  -> Layer 4
```

Reliability enum (top 3 bits), counts over all messages:

| enum | name | reliability byte seen |
|---:|---|---|
| 0 | UNRELIABLE | `0x00` |
| 2 | RELIABLE | `0x50` (+split) |
| 3 | RELIABLE_ORDERED | `0x60`, `0x70` (+split) |

(`1` UNRELIABLE_SEQUENCED and `4` RELIABLE_SEQUENCED are in the model but never showed up in this
capture. They're assumed to follow the same field rules.)

How the offsets were nailed down:
- `dataBitLength` at [+1:+3] big-endian bits. For the single-message UNRELIABLE datagram
  `80 0b7902 00 0048 ...`, `0x0048`=72 bits=9 bytes, and exactly 9 data bytes follow. For
  `... 00 00c8 ...`, `0x00c8`=200 bits=25 bytes, and 25 follow. This holds for every packet, which is
  the tiling check.
- `reliableMessageNumber` at [+3:+6] u24 LE. Over the corpus its distinct values are a
  near-contiguous run, with 97.8% of consecutive-value steps exactly +1 (1,862 / 1,905). A wrong
  offset could not produce a contiguous counter.
- `orderingIndex` at [+6:+9] u24 LE. Same test, 98.4% of steps == +1. It moves in lockstep with
  `reliableMessageNumber` (one channel), and `orderingChannel` = `0x00`.

Result: `rbxraknet.inner.parse()` re-tiles 100.00% (2,379 / 2,379) of DATA datagrams with zero
leftover bytes.

### Layer 2b: split-packet header (10 bytes)

You get this when the reliability byte's bit 4 is set (`0x50`, `0x70`). It sits after the ordering
fields, right before the data fragment:

```
+0   4   splitPacketCount   u32 BE     # fragments in the whole message
+4   2   splitPacketId      u16 BE     rises +1 per split message
+6   4   splitPacketIndex   u32 BE     0,1,2,... fragment ordinal
```

Evidence. 85 clean single-split datagrams all solve to a 10-byte header. Consecutive examples
`...02 0ddb 00000000` then `...02 0ddb 00000001` (same id `0x0ddb`, count 2, indices 0 and 1)
reassemble one >MTU message. `splitPacketId` steps 0ddb, 0ddc, 0ddd. Fragment 0 begins with the
real app id (`830301...`), and later fragments are raw continuation. Reassembly across datagrams is
left to the caller, since the header carries everything needed to do it.

## Layer 3: ACK datagram (`0xd0`), payload is transport-only

`0xd0` datagrams hold acknowledged datagram-number ranges (24-bit LE numbers in the same space as
Layer-1 `datagramNumber`), never replication data, so they're out of the app decode. Lengths
cluster at 13 B (1,535), 16 B (130), 10 B (14).

The exact layout here is a good guess and not confirmed. For example
`d0 0001 00 bbeb01 bdeb01` parses cleanly as
`flag, count=1, minEqualsMax=0, min=0x01ebbb, max=0x01ebbd` (a 3-datagram ack range), but the
13/16-byte forms carry extra trailing 3-byte groups (candidate RakNet `B`/`AS` congestion fields)
that this single form doesn't explain. It wasn't chased, since ACKs carry no replication payload.
`rbxraknet.inner` returns the raw ack bytes and stops.

## Layer 4: application message (inside `data`)

`data[0]` is the Roblox app message id. Histogram over decoded messages:

| app id | count | name |
|---:|---:|---|
| `0x83` | 2742 | ID_DATA (replication container) |
| `0xa1` |  474 | unknown, recurring referent `0x53bc1a`, carries instance refs, no strings |
| others | rare | `0x00/0x03/0xa2/0xa3` and split-continuation first-bytes |

### `0x83` ID_DATA

The framing is measured. The property and event values inside aren't decoded, for the reason at
the end of this section.

`data[1]` is the leading replication block type. Histogram:

| block | count | name | evidence |
|---:|---:|---|---|
| `0x03` | 1641 | PROP (property update) | `83 03 01 <ref:4> <propId:2> <flag> <value...>` blocks, repeated |
| `0x07` |  850 | EVENT (remote/signal) | carries event/ability name strings: "Evade","IFrame","Ragdoll","Knockback","Ultimate" |
| `0x02` |   80 | NEW_INSTANCE? | biggest msgs (to 1 KB); length-prefixed names ("Wakeup","WorldHit","Interp") + attribute dumps |
| `0x06` |   61 | PHYSICS? | fixed 49 B: `<ref> 00000000 <ref> <t1><t2><t3> <counts> ...` |
| `0x05` |   35 | TIME/HEARTBEAT? | fixed 25 B: two increasing 32-bit timestamps |
| `0x23` |   30 | item | referent + `fe0d01` + float triples (CFrame-like) |
| `0x15` |   26 | item | string name + double + floats |
| `0x01`,`0x1b` | 12,7 | item | not detailed |

The counts are measured. The block-type names past PROP and EVENT are proposed readings, not
confirmed.

These replication primitives are present, and `rbxraknet.inner._scan_app` pulls them out:
- Instance referent = 4-byte LE token with a zero high byte. The whole corpus uses three
  families: `0x007e.../0x007d.../0x007c...` (network instances), `0x001f...` (physics-owned), `0x0006...`
  (services). This is how every block names its instance.
- Length-prefixed ASCII strings: `[len:1][bytes]`. These give you class/property/event/attribute
  names ("Ultimate", "Knockback", "RikaSmashService", "OriginalCooldown", ...).
- Typed scalars seen inline: float32 (`cdcc4c3e`=0.2), float64/double (`...5340`~78.7), CFrame-like
  float triples. Value offsets and widths are not confirmed. Roblox serializes property values
  without per-value type tags, and it leans on a class/property SCHEMA to know each field's type
  and width. That schema is sent via `ID_NEW_SCHEMA` on the 0x1f direction, which is still
  ChaCha20-locked and absent from this 0x17 corpus. So walking a block all the way to its exact
  end needs the schema. Without it, a block yields referents and strings and nothing more. That's
  the same wall recorded in PROVENANCE.md.

## Coverage and what remains unknown

- Datagram level: 100% (4,058 / 4,058). Every distinct plaintext is classified, and if it's DATA,
  tiled exactly into messages with zero leftover bytes.
- Transport, reliability, and split (Layers 1, 2, 2b): measured end to end.
- App framing: measured. Message id and `0x83` block type for all decoded messages.
- Still unknown, needs the 0x1f schema:
  1. Property/event value decoding inside `0x83` blocks (needs `ID_NEW_SCHEMA`).
  2. The full `0x83` block grammar past the first block (variable widths, not walkable without the
     schema).
  3. `0xa1` message semantics.
  4. Exact `0xd0` ACK range/congestion layout (transport-only, low value).
  5. Reliability enums 1 and 4, and reassembly of split messages into whole app packets.

Direction note. 0x17 carries `ID_DATA` PROP/EVENT/physics with combat-ability names, so it's a
game replication stream. The companion `0x1f` direction (different cipher) would carry the schema
and the opposite-direction replication.
