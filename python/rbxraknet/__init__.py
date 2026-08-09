"""My decoder for Roblox's RakNet-over-UDMUX protocol.

I reverse-engineered the outer framing and AEAD from live captures. Hand it a
session key for a direction and it decodes real traffic. It leans on
`cryptography` and the stdlib, nothing else. Getting the key yourself is your
problem, I don't do that part here.

    from rbxraknet import parse, AeadCodec, AES, CHACHA
    dg = parse(raw_udp_payload)
    plaintext, counter = AeadCodec(key, AES).decrypt(dg)
"""
from .framing import Datagram, parse
from .aead import AeadCodec, AES, CHACHA, COUNTER_BASE, SALT, nonce, counter_candidates

__all__ = [
    "Datagram", "parse",
    "AeadCodec", "AES", "CHACHA", "COUNTER_BASE", "SALT", "nonce", "counter_candidates",
]
__version__ = "0.1.0"
