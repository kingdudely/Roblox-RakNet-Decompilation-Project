"""AEAD decoder for the repository's existing UDMUX gameplay captures.

This module is separate from the current RbxOpen/SessionCrypto preauth path in
client.py. The captured gameplay layer supports the ciphers already recovered
for those UDMUX frames.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .framing import Datagram

SALT = b"mbeR"
COUNTER_BASE = int.from_bytes(b"UniqueNu", "little")
_MASK16 = 0xFFFF
_DEFAULT_SPAN = 256

AES = "aes-256-gcm"
CHACHA = "chacha20-poly1305"
_CIPHERS = {AES: AESGCM, CHACHA: ChaCha20Poly1305}


def nonce(counter: int) -> bytes:
    return counter.to_bytes(8, "little") + SALT


def counter_candidates(hint: int, span: int = _DEFAULT_SPAN):
    c0 = (COUNTER_BASE & ~_MASK16) | hint
    if c0 < COUNTER_BASE:
        c0 += _MASK16 + 1
    step = _MASK16 + 1
    return (c0 + k * step for k in range(span))


class AeadCodec:
    """Decrypt one UDMUX direction with a recovered 32-byte key."""

    def __init__(self, key: bytes, cipher: str = AES):
        if cipher not in _CIPHERS:
            raise ValueError(f"cipher must be one of {list(_CIPHERS)}")
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self.cipher = cipher
        self._c = _CIPHERS[cipher](key)

    def decrypt(self, dg: Datagram, span: int = _DEFAULT_SPAN):
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
        payload = (
            bytes((FLAG, 0, 0, 0x17))
            + SUBFLAGS
            + bytes(16)
            + ct
            + (counter & _MASK16).to_bytes(2, "little")
            + tag
        )
        return AeadCodec(key, cipher).decrypt(parse(payload), span=span)

    for cipher in _CIPHERS:
        pt, rc = _try(cipher, COUNTER_BASE + 4242, 1)
        assert pt == msg and rc == COUNTER_BASE + 4242, cipher
        wrapped = COUNTER_BASE + 70000
        pt, rc = _try(cipher, wrapped, 2)
        assert pt == msg and rc == wrapped, f"{cipher} wrapped"
    print("[aead] selftest OK")


if __name__ == "__main__":
    _selftest()
