"""Python tooling for Roblox RakNet/session reverse-engineering."""

from .framing import Datagram, parse
from .aead import AeadCodec, AES, CHACHA, COUNTER_BASE, SALT, nonce, counter_candidates
from .sessioncrypto import (
    COUNTER_BASE as SESSION_COUNTER_BASE,
    NONCE_PREFIX,
    NONCE_SUFFIX,
    SessionKdfResult,
    counter_from_hint,
    derive_session_digest,
)

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
    "SESSION_COUNTER_BASE",
    "NONCE_PREFIX",
    "NONCE_SUFFIX",
    "SessionKdfResult",
    "counter_from_hint",
    "derive_session_digest",
]

__version__ = "0.3.0"
