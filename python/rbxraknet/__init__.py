"""Python tooling for Roblox RakNet/session reverse-engineering.

The live bring-up currently stops after RbxOpenReply1. The capture-decoder
modules are retained independently for previously recovered UDMUX traffic.
"""

from .framing import Datagram, parse
from .aead import AeadCodec, AES, CHACHA, COUNTER_BASE, SALT, nonce, counter_candidates

__all__ = [
    "Datagram",
    "parse",
    "AeadCodec",
    "AES",
    "CHACHA",
    "COUNTER_BASE",
    "SALT",
    "nonce",
    "counter_candidates",
]

__version__ = "0.2.0"
