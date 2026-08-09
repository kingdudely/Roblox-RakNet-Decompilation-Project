"""The outer datagram framing for Roblox RakNet.

One UDP payload is laid out on the wire as:

    byte[0]        0x01                      UDMUX/RUPP flag (not a RakNet id)
    byte[1:3]      00 00                      header_len high bytes (always 0)
    byte[3]        0x17 | 0x1f                header_len, also the direction id
    byte[4:7]      01 11 02                   constant sub-flags
    byte[7:23]     epoch_tag (16 bytes)       rotates on re-key epochs
    byte[23:hlen]  mux_extra (8 bytes on 0x1f, empty on 0x17)
    body = payload[hlen:]  =  ciphertext || counter_hint(2, LE) || tag(16)

You get the key from somewhere else. Once you have it, this reads a whole
capture start to finish.
"""
from dataclasses import dataclass

FLAG = 0x01
SUBFLAGS = bytes((0x01, 0x11, 0x02))
DIRECTIONS = (0x17, 0x1F)
_TRAILER = 18  # counter_hint(2) + tag(16)


@dataclass(frozen=True)
class Datagram:
    direction: int
    epoch_tag: bytes
    mux_extra: bytes
    ciphertext: bytes
    counter_hint: int   # low 16 bits of the AEAD nonce counter
    tag: bytes          # GCM/Poly1305, 16 bytes

    @property
    def aead_input(self) -> bytes:
        """Ciphertext glued to tag. That's the buffer the AEAD decryptor wants."""
        return self.ciphertext + self.tag


def parse(payload: bytes) -> Datagram:
    """Turn one raw UDP payload into a Datagram. If the framing is off, this raises ValueError."""
    if len(payload) < 4 or payload[0] != FLAG or payload[1] or payload[2]:
        raise ValueError("not a RakNet/UDMUX datagram")
    hlen = payload[3]
    if hlen not in DIRECTIONS:
        raise ValueError(f"unknown direction/header_len {hlen:#x}")
    if payload[4:7] != SUBFLAGS:
        raise ValueError("bad sub-flags")
    body = payload[hlen:]
    if len(body) < _TRAILER:
        raise ValueError("body shorter than AEAD trailer")
    return Datagram(
        direction=hlen,
        epoch_tag=payload[7:23],
        mux_extra=payload[23:hlen],
        ciphertext=body[:-_TRAILER],
        counter_hint=int.from_bytes(body[-_TRAILER:-16], "little"),
        tag=body[-16:],
    )


def _selftest():
    # round-trip a fake 0x1f datagram through parse()
    epoch = bytes(range(16))
    mux = bytes(range(8))
    ct = b"\xaa" * 40
    hint = 0x1234
    tag = b"\xbb" * 16
    payload = (bytes((FLAG, 0, 0, 0x1F)) + SUBFLAGS + epoch + mux
               + ct + hint.to_bytes(2, "little") + tag)
    dg = parse(payload)
    assert dg.direction == 0x1F and dg.epoch_tag == epoch and dg.mux_extra == mux
    assert dg.ciphertext == ct and dg.counter_hint == hint and dg.tag == tag
    print("[framing] selftest OK")


if __name__ == "__main__":
    _selftest()
