# Android IDA worksheet: first packet first

The immediate goal is NOT Request2 or the KDF. The immediate goal is to reproduce the exact first
RbxOpenRequest1 datagram emitted by the Android x86-64 client.

## A. Fastest route: break on the UDP send

Before reversing the serializer, catch the exact packet the Android client emits. On Android x86-64 the native ABI is SysV AMD64, so a normal `sendto(fd, buf, len, flags, addr, addrlen)` call has `RDI=fd`, `RSI=buf`, `RDX=len`, `RCX=flags`, `R8=addr`, and `R9=addrlen`.

In IDA, import `sendto`/`__sendto_chk` if present, then put a breakpoint on the call reached by the Roblox networking code. When it triggers, dump `RDX` bytes from `RSI`, decode the `sockaddr` at `R8`, and record the local socket with the file descriptor. Also breakpoint `bind` if you need to determine whether the client uses the joinScript `ClientPort`.

The first thing we need is one real retail packet from this breakpoint. It immediately answers packet length, byte 18, destination, and source-port questions.

## B. Find the constructor from the magic

Search for the 16-byte byte sequence:

    00 FF FF 00 FE FE FE FE FD FD FD FD 12 34 56 78

Open every code xref and find the function that writes a nearby leading byte 0x7B and protocol byte 5.
If Hex-Rays has split the constant into two loads, search the dword/qword fragments too.

Once found, rename it `rbx_open_request1_android` and inspect its callers.

## C. Record the exact serialized layout

For the function itself, write down a table:

| offset | size | value/source | evidence |
|---:|---:|---|---|
| 0 | 1 | packet id | instruction |
| 1 | 16 | RakNet magic | instruction |
| 17 | 1 | protocol | instruction |
| 18 | 1 | Rupp opt-in? | instruction |
| 19.. | | padding/other fields | instruction |

Do not assume offset 18 is Rupp until you see the store.

Also capture the final write/cursor and the returned packet length.

## D. Trace the caller

At every call site of the constructor, record:
- the value passed as the output-length/MTU argument;
- the source of MTU;
- the socket send function reached after construction;
- the destination sockaddr/IP/port;
- where the local UDP socket is created/bound and whether a ClientPort-like value is used.

This is the fastest way to separate a bad packet layout from a wrong endpoint/source-port choice.

## E. Compare against the retail packet

Run the real Android client once and capture only the first UDP datagram to the game endpoint.
Do not decrypt anything. Compare:
- packet length;
- first 32 bytes;
- exact destination address/port;
- local source port.

If the Python packet differs, send the two hex prefixes and the four values above. That is enough
to fix the serializer without needing any account material.

## F. Only after Reply1 works

Then move to:
- Request2 constructor
- Rupp/AAD prefix builder
- Reply2 parser
- SessionCrypto key selection
- epoch/rekey

Known Windows-build function names in the branch documentation are leads only; Android addresses and
function boundaries must be rediscovered.