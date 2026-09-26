# Roblox RakNet / SessionCrypto RE

Python working branch for reversing the current Roblox game-server connection path.

## Current status

The branch is intentionally diagnostic at the pre-auth boundary. It does not claim that Request1 is
solved on Android x86-64, and it does not emit Request2.

Relevant Roblox-specific pre-auth IDs:
- 0x7B RbxOpenRequest1
- 0x7E RbxOpenReply1
- 0x78 RbxOpenRequest2
- 0x7D RbxOpenReply2

Issue #1 in topologyorgboi's original project is useful here: the author confirms that 0x7B/0x7E/0x78/0x7D
are the pre-connection layer and that the body begins with the standard RakNet offline magic. The same issue
also explicitly says the handshake reversal was a gap in that project rather than a solved implementation.

## Important corrections to this branch

- GameJoin RakNetEarlyPublicKey data now defaults to version id 2, matching the documented JoinInformation
  shape in the original project's WEB_JOIN_FLOW notes.
- Request1 Rupp opt-in is configurable; the Python diagnostic defaults it to 0 until the Android target
  confirms byte 18. The earlier hard-coded value 1 was a Windows-build finding and was not enough evidence
  to claim that the Android client uses the same value.
- UDP source port is configurable and defaults to the joinScript ClientPort when present.
- You can test each UDMUX endpoint or the MachineAddress:ServerPort target separately.

## Current Request1 serializer

Current diagnostic serializer is:

    [0x7B]
    [16-byte RakNet magic]
    [protocol = 5]
    [Rupp opt-in = 0 or 1]
    [zero padding]

The current length formula remains MTU - 40 because that is the existing Windows IDA finding. This is
also still an Android verification target. Do not treat the length as settled until the Android constructor
or a captured retail packet confirms it.

## IDA priority

Start with the Android equivalent of the Request1 constructor. In IDA, search for the 16-byte constant:

    00 FF FF 00 FE FE FE FE FD FD FD FD 12 34 56 78

Then follow the xrefs to the function that writes the leading packet id and protocol byte. Record:

1. exact buffer base and cursor/offset before the first write;
2. packet id byte;
3. the 16-byte magic write;
4. protocol byte;
5. byte immediately after protocol (the suspected Rupp opt-in);
6. all subsequent writes and the final returned length;
7. the argument at the call site that controls the output length;
8. the destination IP/port and local bind-port setup at the caller.

Do not transfer Windows RVAs to Android. Use the constant and call graph to identify the equivalent function.

## SessionCrypto findings already supported

For the documented Windows build 9.4.260915.1d72b8c0:

    shared = X25519(local_private, peer_public)
    digest = SHA512(shared || local_public || peer_public)

The Python implementation exposes that derivation but does not label digest halves as packet keys.
The nonce construction is LE64(counter) || b'mbeR' with initial LE64('UniqueNu').

## Bring-up

First test the UDP boundary rather than attempting Request2:

    python -m rbxraknet.client --place-id YOUR_PLACE_ID --udp-trace --all-endpoints

Then test the alternate Rupp byte:

    python -m rbxraknet.client --place-id YOUR_PLACE_ID --udp-trace --rupp-opt-in 1

Then test the server endpoint if UDMUX does not answer:

    python -m rbxraknet.client --place-id YOUR_PLACE_ID --udp-trace --machine-address

To force a source port, add `--local-port PORT`.

Do not copy cookies, authentication tickets, or live session keys into the repository.