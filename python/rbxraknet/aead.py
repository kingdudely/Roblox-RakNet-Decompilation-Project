"""The AEAD layer for Roblox RakNet.

The nonce is 12 bytes, made of LE64(counter) followed by b"mbeR". The counter
starts at LE64(b"UniqueNu") = 8452805105709313621 and goes up by one for every
packet in a direction. The full 12-byte magic is "UniqueNumbeR", so the nonce is
really that magic split around the counter. Only the low 16 bits of the counter
(the counter_hint) actually go over the wire. So to get the real counter back I
try the values that match the hint mod 2^16 near the base, and stop when the tag
authenticates.

There's no AAD. Each direction gets its own key and its own counter. The sessions
I captured used AES-256-GCM (format 2) in both directions. ChaCha20-Poly1305
(format 0) also shows up when a session negotiates it, so I wired up both ciphers.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .framing import Datagram

SALT = b"mbeR"
COUNTER_BASE = int.from_bytes(b"UniqueNu", "little")   # 8452805105709313621
_MASK16 = 0xFFFF
_DEFAULT_SPAN = 256                                    # enough to cover sessions up to 2^24 packets

AES = "aes-256-gcm"
CHACHA = "chacha20-poly1305"
_CIPHERS = {AES: AESGCM, CHACHA: ChaCha20Poly1305}


def nonce(counter: int) -> bytes:
    return counter.to_bytes(8, "little") + SALT


def counter_candidates(hint: int, span: int = _DEFAULT_SPAN):
    """Every full counter that matches hint (mod 2^16), from BASE up to BASE + span*2^16."""
    c0 = (COUNTER_BASE & ~_MASK16) | hint
    if c0 < COUNTER_BASE:
        c0 += _MASK16 + 1
    step = _MASK16 + 1
    return (c0 + k * step for k in range(span))


class AeadCodec:
    """Holds one key and cipher for one direction. Call decrypt() and you get back (plaintext, counter)."""

    def __init__(self, key: bytes, cipher: str = AES):
        if cipher not in _CIPHERS:
            raise ValueError(f"cipher must be one of {list(_CIPHERS)}")
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self.cipher = cipher
        self._c = _CIPHERS[cipher](key)

    def decrypt(self, dg: Datagram, span: int = _DEFAULT_SPAN):
        """Authenticate and decrypt a Datagram. If no counter works out, you get (None, None)."""
        blob = dg.aead_input
        for c in counter_candidates(dg.counter_hint, span):
            try:
                return self._c.decrypt(nonce(c), blob, b""), c
            except Exception:
                continue
        return None, None


def _selftest():
    from .framing import parse, FLAG, SUBFLAGS
    msg = b"replication " * 4

    def _try(cipher, counter, span):
        key = bytes(range(32))
        ct_tag = _CIPHERS[cipher](key).encrypt(nonce(counter), msg, b"")
        ct, tag = ct_tag[:-16], ct_tag[-16:]
        payload = (bytes((FLAG, 0, 0, 0x17)) + SUBFLAGS + bytes(16)
                   + ct + (counter & _MASK16).to_bytes(2, "little") + tag)
        return AeadCodec(key, cipher).decrypt(parse(payload), span=span)

    for cipher in _CIPHERS:
        pt, rc = _try(cipher, COUNTER_BASE + 4242, 1)          # first 2^16 window
        assert pt == msg and rc == COUNTER_BASE + 4242, cipher
        wrapped = COUNTER_BASE + 70000                          # past 2^16, needs span >= 2
        pt, rc = _try(cipher, wrapped, 2)
        assert pt == msg and rc == wrapped, f"{cipher} wrapped"
    print("[aead] selftest OK (both ciphers, k=0 and wrapped counter recovered)")


if __name__ == "__main__":
    _selftest()
