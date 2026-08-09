# Roblox web join flow and the RakNet AEAD session key

The RakNet transport encrypts each direction with a 32-byte key, either AES-256-GCM or
ChaCha20-Poly1305. Those keys live inside the client, in the RakPeerCrypto structure. The
question this doc answers is whether you can pull them out of the HTTPS join responses, or
whether the client agrees on them separately so the web join never carries them.

It's the second one. The join response hands you both public keys, the client's and the
server's, plus a seed. It never hands you a private scalar or the raw symmetric key, so you
can't rebuild the AEAD key from captured HTTPS, and the key is ephemeral for the session anyway.
The evidence follows.

A note on sourcing. Field names and endpoints come from Roblox's tracked GameJoin Swagger and the
decompiled client model unless said otherwise. Claims that read the field shapes rather than quote
a source are called out as such, and so are the parts no public source documents.

## The ordered HTTPS join flow, with endpoints and the fields that matter

The hostnames and endpoints below match Roblox's tracked Swagger (`gamejoin.roblox.com` GameJoin
Api v1) and independent API-doc mirrors. The field names match that same Swagger and the
decompiled client's `JoinInformation` model.

### Step 0: hold a session

You start with a `.ROBLOSECURITY` cookie for an authenticated Roblox web session.

### Step 1: CSRF token

State-changing POSTs to `*.roblox.com` need an `X-CSRF-TOKEN`. POST with a blank token, read the
real token back from the `x-csrf-token` response header on the 403 that comes back, then reuse it.

### Step 2: authentication ticket

`POST https://auth.roblox.com/v1/authentication-ticket/` with the headers
`Cookie: .ROBLOSECURITY`, `X-CSRF-TOKEN`, `RBXAuthenticationNegotiation: 1`, and
`Referer: https://www.roblox.com/...`. The one-time ticket comes back in the
`rbx-authentication-ticket` response header, and the body is empty. Leave off
`RBXAuthenticationNegotiation` and you get a 400. This ticket is a short-lived redemption token,
not key material.

### Step 3: PlaceLauncher, start or find the job (poll)

`GET/POST https://gamejoin.roblox.com/v1/...` (older clients hit
`www.roblox.com/game/PlaceLauncher.ashx`). You poll a status enum until a server gets assigned.
`0` is waiting, `1` is loading, `2` is joining, with error codes 3, 4, 5, 6, and 10 through 17.
The payload carries `jobId`, `joinScriptUrl`, `authenticationUrl`, `authenticationTicket`,
`status`, and `message`. The status ladder is documented in RFD and the Daniel-176 RE wiki.

### Step 4: the join call that returns the crypto material

All of these POST to `https://gamejoin.roblox.com`, and the Swagger lists each path:
`/v1/join-game` (`GameJoinRequest`), `/v1/join-game-instance` (a specific `gameId` or jobId,
including `cId`), `/v1/join-private-game`, `/v1/join-reserved-game` (accessCode or linkCode),
`/v1/play-with-user`, `/v1/join-play-together-game`, and `/v1/team-create`. The redeemed auth
ticket rides in the `RBX-Authentication-Ticket` header.

The response is a `GameJoinResponse`:

```
status:int  message:str  jobId:str  queuePosition:int
joinScriptUrl:str  authenticationUrl:str  authenticationTicket:str
statusData:{creatorExperienceBan:{...}}
joinScript: JoinInformation        <- the payload the client actually connects with
```

The `joinScript` comes down as signed JSON, wrapped in `--rbxsig2%...%` or `--rbxsig4%...%`
(RSA-1024, X509/PKCS7). That signature proves the joinScript is authentic. It is not transport
encryption and carries no session key. This is documented in the RRE Signatures doc, and RFD
emits `--rbxsig2%0%` prefixes.

### JoinInformation (the joinScript): the fields that matter

Connection targets: `MachineAddress:str`, `ServerPort:int`, `UdmuxEndpoints:[{Address,Port}]`
(the UDMUX relay endpoints), `ServerConnections:[{Address,Port}]`, `ClientPort`, `GameId` (the
jobId), `PlaceId`, `UniverseId`, `DataCenterId`, `RccVersion`, `PingUrl`, and `BaseUrl`.

Identity and session: `UserId`, `UserName`, `DisplayName`, `AccountAge`, `MembershipType`,
`SessionId:str`, `AnalyticsSessionId`, and `ClientTicket:str` (redeemed to the game server
in-band, described in step 5).

The crypto-relevant fields are confirmed present in the model. The roles below are read from
their names, sizes, and encodings.

`ClientPublicKeyData:str` is a JSON string. Its decoded shape, taken from the open-source
Roblox-Freedom-Distribution server that reproduces the client's expected format, is:

```json
{"creationTime":"...",
 "applications":{
   "RakNetEarlyPublicKey":{
     "versions":[{"id":2,"value":"<base64 32-byte key>","allowed":true}],
     "send":2,"revert":2}}}
```

The `value` base64 decodes to exactly 32 bytes, confirmed by decoding the sample
(`1f06ad7c...d85c8f6c`). That is the size of a Curve25519 / X25519 public key, and the application
is named `RakNetEarlyPublicKey`. Both of those facts are measured. Reading the value as an X25519
public key is the deduction they support.

`EphemeralEarlyPubKey:str` is a second public key, the counterpart to the one above, confirmed
present in the model. `RandomSeed1:str` is typed `format: byte` in the Swagger (base64 bytes),
which makes it a seed. `TokenGenAlgorithm:int`, `TokenValue:str`, and `PepperId:int` belong to
the packet-level security-token system used for anti-tamper, which is separate from the AEAD key
(see the re-key section).

The absences matter too. When you fully enumerate the `JoinInformation` fields, there's no field
named `SessionKey`, `AesKey`, `SharedSecret`, `PrivateKey`, or anything like that.

### Step 5: RakNet over UDMUX (UDP)

The client opens a RakNet connection to a `UdmuxEndpoints` entry (or to
`MachineAddress:ServerPort`). The offline handshake runs `UNCONNECTED_PING/PONG`, then
`OPEN_CONNECTION_REQUEST/REPLY 1&2`, then `CONNECTION_REQUEST/ACCEPTED`. The client then submits
its `ClientTicket` to the game server in-band, through the RakNet packet `ID_SUBMIT_TICKET`
(`0x8A`), so the server can authenticate it. This is confirmed by the packet-id table. Once
connected, application traffic (`ID_DATA` `0x83`, `ID_PHYSICS` `0x85`, and so on) is AEAD-wrapped
with the per-direction keys.

## Is the AEAD key recoverable from HTTPS?

No. The key is set up by an ephemeral X25519 ECDH. Its public halves travel over HTTPS, but its
private scalar only ever lives in the client, so it isn't present in the HTTPS responses in any
form you can turn into it.

The chain:

1. The joinScript carries two 32-byte public keys, not a symmetric key. The client's key is
   `ClientPublicKeyData.applications.RakNetEarlyPublicKey.value` (32 bytes), the server-side key
   is `EphemeralEarlyPubKey`, and it also carries the `RandomSeed1` seed. Confirmed from the
   model.
2. Those names and sizes come from Roblox's GameJoin Swagger and the decompiled client
   `JoinInformation` model, and roughly ten independent open-source Roblox-server
   reimplementations that populate `RakNetEarlyPublicKey` back them up.
3. Two 32-byte "Ephemeral/Early Public Keys" plus a seed is the shape of an X25519 key
   agreement: `shared = X25519(own_private, peer_public)`, then `keys = KDF(shared, RandomSeed1,
   ...)`. The word "Early" points to a 0-RTT exchange, where the public keys are pre-shared through
   the web join so the client can encrypt from its very first RakNet datagram without an extra UDP
   round trip. This reads the field shapes rather than quoting a source, and it's a strong
   inference.
4. In ECDH the private keys never go on the wire. The joinScript hands you both public keys and
   the salt, which is not enough to compute the shared secret. A passive observer who fully
   decrypts the TLS join can verify a key but cannot derive one. That's just a property of the
   algorithm.
5. The independent `rbxraknet` inspector never derives keys from HTTPS or handshake bytes. Its
   only key sources are the running process's `RakPeerCrypto` struct, a live Wireshark dissector,
   or a manual paste. If the key were sitting in the join response, a packet tool would read it
   there. It doesn't, because it can't. (The struct offsets that tool uses come from a
   reverse-engineered source and are not confirmed.)

The UDP handshake doesn't carry it in cleartext either. `OPEN_CONNECTION_REQUEST/REPLY` and
`CONNECTION_REQUEST` carry GUIDs, MTU, and a `use_security` / `use_encryption` boolean, confirmed
by the handshake decoder fields. They carry no raw key bytes and no in-band public-key exchange,
and Roblox doesn't use RakNet's legacy built-in ECC secure-connection handshake here. So the
secret is in neither the HTTPS body nor the UDP handshake. It's the ECDH output of a
web-pre-shared public-key pair, computed independently on each end.

## Epoch and re-key rotation (the 16-byte epoch_tag)

No public source documents the re-key derivation. Nothing in this section is confirmed: it reads
the verified architecture plus one design tell, and stops there.

The reading is that a re-key installs a new key for a new epoch, rather than continuing the same
key under a fresh nonce base. The reasoning:

- At re-key you see a fresh 16-byte `epoch_tag`, and the nonce counter returns to its `"UniqueNu"`
  base. With AES-GCM or ChaCha20 a (key, nonce) pair must never repeat, so a continuing key would
  keep counting the nonce upward instead of resetting it. A reset base implies a new key.
- The `epoch_tag` looks like a key or epoch identifier, the field the receiver uses to pick which
  key decrypts a datagram: a truncated hash of the new epoch key, or a salt fed into that epoch's
  KDF. Its 16-byte width fits a key id or salt, not a key.
- Derivation would then be a ratchet or KDF over the original ECDH secret plus an epoch counter,
  possibly mixing in `RandomSeed1` or `PepperId`, so `epoch_key = KDF(session_secret,
  epoch_index)`. No public artifact names the KDF, its labels, or whether `epoch_tag` is an input
  or an output.
- One design tell is confirmed. The `rbxraknet` tool ships a session-key hot-reload that re-reads
  keys from disk when they change mid-capture. A tool only needs that if the live keys rotate
  during a session and each new key has to be re-extracted from memory, which fits per-epoch new
  keys and not one key under a new nonce base.

So for a whole session you need one key per epoch, and each key was resident in `RakPeerCrypto`
only while its epoch was active, so a key extracted once decrypts only its own epoch.

## The UniqueNumbeR nonce law

The nonce construction is confirmed by the independent `rbxraknet` source and by direct decoding.
The base string is the 12 bytes `"UniqueNumbeR"`. The 12-byte nonce is `LE64(counter) || "mbeR"`,
meaning the first 8 bytes get overwritten with the little-endian counter and the trailing
`"mbeR"` is kept. The counter base is `LE64("UniqueNu") = 0x754E657571696E55 =
8452805105709313621`, incremented by 1 per packet per direction. Each packet carries only the low
16 bits as a `counter_hint` (2 bytes little-endian) placed before the 16-byte tag, so the wire
layout is `ciphertext || counter_hint(2, LE) || tag(16)`, and the full counter is reconstructed by
signed-diff wraparound. The AAD is empty. The cipher is chosen by the format byte, where
`format & 2` selects AES-256-GCM and otherwise it's ChaCha20-Poly1305 (IETF), which is "format 0".

The `rbxraknet` README says the repo is a partly reverse-engineered rebuild. The nonce law and
cipher selection are independently confirmed by direct decoding and you can treat them as solid,
but the repo's exact `RakPeerCrypto` offsets should be treated as unconfirmed.

## What this means for headless decryption without opening Roblox

Capture-only decryption isn't going to work. Even with the `.ROBLOSECURITY` cookie and full TLS
interception of the join, all you get is the endpoints, the `ClientTicket`, both public keys, and
`RandomSeed1`, never a private scalar and never the symmetric key.

There are two recovery paths, and each needs an endpoint secret:

1. Be the client. Generate your own X25519 pair, drop your public key into
   `ClientPublicKeyData.applications.RakNetEarlyPublicKey`, keep the private key, and compute
   `X25519(your_priv, EphemeralEarlyPubKey)` followed by the KDF. That basically means writing a
   client, and the exact KDF (its labels, seed mixing, and epoch ratchet) is unconfirmed and has
   to be reversed from the binary first.
2. Lift the live key material from the running process (`RakPeerCrypto`) or from a Wireshark
   key-log dissector at connect time. This needs Roblox running, so it isn't decryption "without
   opening Roblox".

Both paths are per-session, and per-epoch if the session re-keys. Plan for a stream of keys, with
hot-reload on rotation. The keys sit in client memory because they're ECDH outputs, never because
they were sent.

## Sources

Roblox GameJoin, auth, and join-flow specs and field schemas:

- Roblox GameJoin Api v1 Swagger (tracked): https://github.com/Paficent/Roblox-Api-Tracker/blob/main/gamejoin/v1.json
- Roblox-Client-Tracker, decompiled `JoinInformation` OpenAPI model: https://github.com/MaximumADHD/Roblox-Client-Tracker (path `CompiledPackages/OpenApiGameJoinApiv1/.../Models/JoinInformation.luac.s`)
- `synpixel/roblox-api-types` gamejoin type defs: https://github.com/synpixel/roblox-api-types/blob/main/types/gamejoin.luau
- `AlroviOfficial/RoZod` gamejoin v1 endpoints: https://github.com/AlroviOfficial/RoZod/blob/main/src/endpoints/gamejoinv1.ts
- `NoTwistedHere/Roblox-Apis`, gamejoin.roblox.com.md and auth.roblox.com.md: https://github.com/NoTwistedHere/Roblox-Apis/tree/main/Documentations
- ROBLOX Reverse-Engineering, JoinScripts and Signatures docs: https://docs.robloxreverseengineering.net/ (repo: https://github.com/ROBLOX-Reverse-Engineering/RRE-Site)
- Roblox DevForum GameJoin threads: https://devforum.roblox.com/t/help-with-gamejoin-api/1740897

`ClientPublicKeyData`, `RakNetEarlyPublicKey`, and `EphemeralEarlyPubKey` internal shape, from
open-source Roblox-server reimplementations that populate them:

- `Windows81/Roblox-Freedom-Distribution`, .../Source/web_server/endpoints/join_data.py (also `orblua/RobloxCore` joinscript.py and `noobwarrior-org/noobwarrior` JoinScriptJsonHandler.cpp)
- PlaceLauncher status ladder: https://github.com/Daniel-176/Roblox-Reverse-Engineering-Wiki/blob/main/articles/client/placelauncher-status.md

RakNet AEAD, nonce law, and key-extraction lineage:

- `sajicooltoday/openwrt-rbxraknet` (packet inspector; README notes it is reverse-engineered): https://github.com/sajicooltoday/openwrt-rbxraknet, key files `raknet/{keygen,crypto,handshake,constants}.lua`

Auth-ticket flow, `auth.roblox.com/v1/authentication-ticket` plus the `rbx-authentication-ticket`
header and `RBXAuthenticationNegotiation`: NoTwistedHere/Roblox-Apis auth doc (above), and
`ic3w0lf22/Roblox-Account-Manager` Account.cs.

Crypto background: X25519, https://cryptography.io/en/stable/hazmat/primitives/asymmetric/x25519/ ; RFC 8418, https://datatracker.ietf.org/doc/html/rfc8418
