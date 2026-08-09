"""Take one decrypted Roblox-RakNet datagram and turn it into a structured tree.

What goes in is a single decrypted plaintext, so framing.parse and
aead.AeadCodec have already peeled off the AEAD by the time you get here. What
comes out looks like this:
    datagram -> {flags, type, datagram_number, messages[]}
    message  -> {reliability, reliable_message_number, ordering_index,
                 ordering_channel, split{}, data_bits, app{}}
    app      -> {id, name, block_type, block_name, referents[], strings[], raw}

Here's why I trust this. The transport, reliability, and split framing re-tile
every distinct DATA datagram in the capture with zero bytes left over, and the
reliable_message_number and ordering_index I pull out come back as contiguous +1
counters (INNER_PROTOCOL.md has the details). The app id (0x83 ID_DATA) and its
block type both fell out of a histogram.

I don't decode property and event values. Roblox serializes them with no type
tags, driven by a class/property schema that rides in ID_NEW_SCHEMA. Without
that schema I can't know the field widths, so the referent and string extraction
below is just a best-effort structural scan. Treat it as a heuristic.

Every field is byte-aligned, so this reads bytes and not bits. Multi-byte
counters are little-endian. dataBitLength and the split header are big-endian.
"""
import string

# the RakNet flag byte is a bitmask. bit7 (0x80) means isValid and bit6 (0x40)
# means isACK. so DATA is valid and not ack (I've seen 0x80, 0x81, 0x82, 0x83,
# where the low bits are packet-pair and continuous-send hints that don't move
# the header around). ACK is valid and ack (0xc0 and 0xd0). parse() decides by
# the mask, so an oddball flag like 0x83 still tiles, and the exact-tile check
# throws out anything that isn't really a datagram.
VALID, IS_ACK = 0x80, 0x40
DATA_FLAGS = frozenset((0x80, 0x81, 0x82, 0x83))   # just for reference and tests, parse() uses the mask
ACK_FLAGS = frozenset((0xC0, 0xD0))

RELIABILITY = {0: "UNRELIABLE", 1: "UNRELIABLE_SEQUENCED", 2: "RELIABLE",
               3: "RELIABLE_ORDERED", 4: "RELIABLE_SEQUENCED"}
APP_ID = {0x83: "ID_DATA", 0xa1: "ID_UNKNOWN_A1?"}          # 0xa1 name is a guess
DATA_BLOCK = {0x01: "ITEM_01?", 0x02: "NEW_INSTANCE?", 0x03: "PROP", 0x05: "TIME?",
              0x06: "PHYSICS?", 0x07: "EVENT", 0x15: "ITEM_15?", 0x1b: "ITEM_1B?",
              0x23: "ITEM_23?"}

_u16be = lambda b, o: (b[o] << 8) | b[o + 1]
_u24le = lambda b, o: b[o] | b[o + 1] << 8 | b[o + 2] << 16
_u32be = lambda b, o: int.from_bytes(b[o:o + 4], "big")
_PRINTABLE = set(string.ascii_letters + string.digits + "_ ")


class ParseError(ValueError):
    pass


def _scan_app(data: bytes) -> dict:
    """A best-effort scan over one app-layer body. It's a heuristic and it doesn't decode the values."""
    app = {"id": data[0], "name": APP_ID.get(data[0], f"0x{data[0]:02x}?"),
           "block_type": None, "block_name": None, "referents": [], "strings": [],
           "raw": data.hex()}
    if data[0] == 0x83 and len(data) > 1:
        app["block_type"] = data[1]
        app["block_name"] = DATA_BLOCK.get(data[1], f"0x{data[1]:02x}?")
    refs = []
    for o in range(2, len(data) - 3):
        if data[o + 3] == 0x00 and data[o + 2] in (0x7c, 0x7d, 0x7e, 0x1f, 0x06, 0x53):
            refs.append(_u24le(data, o))
    app["referents"] = sorted(set(refs))[:32]
    o = 2
    while o < len(data):
        n = data[o]
        if 1 <= n <= 48 and o + 1 + n <= len(data):
            chunk = data[o + 1:o + 1 + n]
            if all(chr(c) in _PRINTABLE for c in chunk):
                app["strings"].append(chunk.decode("ascii"))
                o += 1 + n
                continue
        o += 1
    return app


def parse(pt: bytes) -> dict:
    """Decode one decrypted plaintext. If the shape isn't one I model it raises
    ParseError, and a DATA datagram has to tile exactly or it's not valid."""
    if not pt:
        raise ParseError("empty plaintext")
    flags = pt[0]
    if not flags & VALID:
        raise ParseError(f"unknown leading flag 0x{flags:02x}")
    if flags & IS_ACK:
        return {"flags": flags, "type": "ACK", "ack_raw": pt[1:].hex(),
                "datagram_number": None, "messages": []}
    if len(pt) < 4:
        raise ParseError("truncated datagram header")

    out = {"flags": flags, "type": "DATA", "datagram_number": _u24le(pt, 1), "messages": []}
    o, n = 4, len(pt)
    while o < n:
        rb = pt[o]; rel = rb >> 5; split = (rb >> 4) & 1; o += 1
        if o + 2 > n:
            raise ParseError(f"truncated dataBitLength at {o}")
        data_bits = _u16be(pt, o); o += 2
        dlen = (data_bits + 7) // 8
        msg = {"reliability": RELIABILITY.get(rel, f"REL{rel}"), "reliability_id": rel,
               "reliable_message_number": None, "ordering_index": None,
               "ordering_channel": None, "split": None, "data_bits": data_bits}
        if rel in (2, 3, 4):
            if o + 3 > n:
                raise ParseError("truncated reliableMessageNumber")
            msg["reliable_message_number"] = _u24le(pt, o); o += 3
        if rel in (1, 3, 4):
            if o + 4 > n:
                raise ParseError("truncated orderingIndex")
            msg["ordering_index"] = _u24le(pt, o)
            msg["ordering_channel"] = pt[o + 3]; o += 4
        if split:
            if o + 10 > n:
                raise ParseError("truncated split header")
            msg["split"] = {"count": _u32be(pt, o), "id": _u16be(pt, o + 4),
                            "index": _u32be(pt, o + 6)}
            o += 10
        if o + dlen > n:
            raise ParseError(f"message data overruns datagram ({o}+{dlen}>{n})")
        data = pt[o:o + dlen]; o += dlen
        if not split or msg["split"]["index"] == 0:
            msg["app"] = _scan_app(data) if data else None
        else:
            msg["app"] = {"id": None, "name": "SPLIT_CONTINUATION", "raw": data.hex()}
        out["messages"].append(msg)
    if o != n:
        raise ParseError(f"datagram did not tile exactly ({o}!={n})")
    return out


def decode_inner(pt: bytes) -> dict:
    """Same as parse() but it never raises. Anything I don't model comes back as
    {'type': 'UNMODELED', ...} so your decode loop can just keep going."""
    try:
        return parse(pt)
    except ParseError as e:
        return {"type": "UNMODELED", "flags": pt[0] if pt else None,
                "reason": str(e), "raw": pt.hex()}


def _selftest():
    body = bytes([0x83, 0x03, 0x01]) + b"\x11\x22\x7e\x00"
    dbits = len(body) * 8
    dg = (bytes([0x80, 0x0b, 0x79, 0x02, 0x60]) + bytes([dbits >> 8, dbits & 0xFF])
          + bytes([0xb8, 0x25, 0x02]) + bytes([0x75, 0xfd, 0x01, 0x00]) + body)
    t = parse(dg)
    assert t["type"] == "DATA" and t["datagram_number"] == 0x02790b
    m = t["messages"][0]
    assert m["reliability"] == "RELIABLE_ORDERED"
    assert m["reliable_message_number"] == 0x0225b8 and m["ordering_index"] == 0x01fd75
    assert m["app"]["name"] == "ID_DATA" and m["app"]["block_name"] == "PROP"
    assert decode_inner(b"\x99\x00")["type"] == "UNMODELED"
    print("[inner] selftest OK (DATA tiles; unmodeled shape degrades gracefully)")


if __name__ == "__main__":
    _selftest()
