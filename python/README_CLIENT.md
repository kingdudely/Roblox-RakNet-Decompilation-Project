# Python branch: live join bring-up

This branch adds a minimal executable Python front end around the repository's
current Roblox RakNet reverse-engineering work.

## Install

    cd python
    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -r requirements.txt

For tests:

    python -m pip install pytest
    python -m pytest

## Commands

Web join + X25519 + SHA-512:

    python -m rbxraknet.client --place-id 12345

Specify a server JobId:

    python -m rbxraknet.client --place-id 12345 --job-id YOUR_JOB_ID

Probe the returned UDMUX endpoint:

    python -m rbxraknet.client --place-id 12345 --probe

Run the standard RakNet connection negotiation:

    python -m rbxraknet.client --place-id 12345 --handshake

Run both:

    python -m rbxraknet.client --place-id 12345 --probe --handshake

The cookie is read from ROBLOSECURITY or prompted with hidden input. It is
never printed.

## Current boundary

The repository's own build-specific provenance confirms the X25519 operation and
the SHA-512 input:

    SHA512(
        X25519(local_private, EphemeralEarlyPubKey)
        || local_public
        || EphemeralEarlyPubKey
    )

The same provenance still says that the exact 64-byte digest -> two AEAD keys
mapping, epoch rekey, and concrete Rupp token generator are unresolved.

The Python branch therefore does NOT call digest[:32] / digest[32:] the real
keys. It proves the parts that can actually be tested now and stops cleanly
before pretending the encrypted gameplay session is complete.

The existing rbxraknet.aead and rbxraknet.inner modules are already ready for
the live authenticated stream once the key/epoch derivation is established.
