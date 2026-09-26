# IDA worksheet: Roblox game-server connection / SessionCrypto

Target build currently documented in this branch: 9.4.260915.1d72b8c0 (x86-64).
Android x86-64 / libroblox.so may have different addresses.

The branch deliberately records only findings tied to concrete code paths. Use the following targets
in IDA and send back the decompiler output, call arguments, or screenshots for unresolved items.
Do not send account cookies, auth tickets, or live session keys.

## 1. Confirm the first UDP stage

Locate:
- sub_2897560 — RbxOpenRequest1 constructor.
- sub_28979D0 — alternate Rupp-header path.
- sub_2897F00 — RbxOpenReply1 parser.
- sub_2898470 — RbxOpenRequest2 constructor.
- sub_28994F0 — server-side Request2 parser.
- sub_289BDF0 — client-side Reply2 parser.
- sub_289B300 — Reply2 constructor.

For each function, record the exact argument list after applying a plausible __fastcall prototype, every
Read/Write/Serialize operation that advances a buffer/bit cursor, constants and lengths used by those
writes, and the caller immediately above it plus the callee immediately below any crypto operation.

For sub_2898470, record the write order and cursor position immediately before and after:
- 0x78
- the 16-byte RakNet magic
- 0x03
- 0x00
- the two 16-bit fields
- the 32-byte local public key

Then continue until the function returns the final packet length.

## 2. Recover the Request2 AAD prefix

Locate sub_289FC80 — offline/Rupp prefix builder.

Do not reverse the token algorithm first. We only need the serialized prefix layout.
Record the returned pointer/length pair (or output buffer + final cursor), every byte/bit write, all
conditional branches and which joinScript/runtime field controls them, and the final AAD length.

The server parser sub_28994F0 reads an AAD length and rejects values below 0x35.
The goal is a deterministic Python serializer for this prefix.

## 3. Pin down SessionCrypto fields

Locate:
- sub_28DD1B0 — 352-byte SessionCrypto workspace.
- sub_28B9FD0 — peer-key copy / handoff.
- sub_28C0B20 — X25519 + SHA-512 derivation.
- sub_28BA1D0 — AEAD decrypt path.
- sub_28BA070 — 12-byte nonce construction.
- sub_28DD510 — state use immediately around AEAD.

Temporarily name the workspace fields:
- +0x00 local_pub
- +0x20 local_private
- +0x40 peer_pub
- +0xC0 kdf_scratch
- +0xE0 kdf_output

Trace reads and writes to +0xE0..+0x11F.
The critical question is where the two 32-byte packet keys are selected from the 64-byte SHA-512 result.
Search for 32-byte copies from +0xE0 and for calls that consume exactly 32 bytes as a symmetric key.

## 4. Recover epoch/rekey behavior

The outer UDMUX datagram contains a 16-byte epoch tag at bytes [7:23].
Find all xrefs to the SessionCrypto epoch field and code that compares, copies, or hashes it.
Pay particular attention to the first call after the client accepts an epoch change.

Record:
- source buffer
- destination buffer
- hash/AEAD primitive used
- exact input ordering
- output length
- whether the existing packet key or ECDH output is used

Do not infer HKDF labels unless the binary actually supplies them.

## 5. Recover the Rupp token generator last

Known chain:
sub_2275560 -> sub_2275400 -> object at a1+0x40 -> vtable+0x10 -> 16-byte token -> sub_2275C70

Also inspect:
- SetTokenValue -> qword_7DB7010
- SetTokenGenAlgo -> unk_85C9DD0
- SetTokenPepper -> unk_85C9DE8

The highest-value next result is the concrete function behind vtable + 0x10.
Trace its byte/string operations and identify whether it calls a standard hash/MAC primitive.

## 6. Useful IDA output to send back

For each target, the most useful form is either the Hex-Rays pseudocode for the whole function or a
screenshot showing the function, local variables, and relevant xrefs.
For large functions, send only sections containing buffer writes, crypto calls, and branches that select fields.
Keep the original function name/address visible so they can be mapped to the repo notes.

### Android x86-64 note

Because this target is libroblox.so, the same semantic function may have a different address than the
Windows build. Do not transfer sub_28C0B20-style names or RVAs directly between platforms.
Use constants, string references, and the call graph to identify the corresponding Android function.

A good place to start is the Android equivalent of sub_2898470, because it gives the first complete view
of exact Request2 wire construction.
