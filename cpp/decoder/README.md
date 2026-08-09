# rbxraknet-cpp

C++ port of the decoder for Roblox's RakNet-over-UDMUX transport. It parses the self-describing
outer datagram header. Nonce counters are tracked per direction and per epoch, and both AEAD
suites run through OpenSSL EVP.

Research and learning only. It works offline on a capture file, with no network access and no
reads of another process's memory. The outer framing is checked against 16,797 live datagrams.
The AEAD suite, the nonce, and the per-direction keys were measured by the Python reference
decoder in `../../python`, where both directions came out as AES-256-GCM. This port ships no key
of its own, and its AEAD tests run on a synthetic key. The claim-by-claim ledger is in
`../../docs/PROVENANCE.md`.

## Toolchain

Built and tested with MinGW g++ 16.1.0 and CMake 4.2 (MinGW Makefiles), against the MinGW
OpenSSL 3.6 under `C:/ProgramData/mingw64/mingw64/opt`. There's also an MSVC (`/W4`) path in
`CMakeLists.txt`, but MSVC wants its own OpenSSL build and hasn't been run, so treat it as
untested.

## Build

```sh
# from the repo root; g++, gcc, mingw32-make and cmake on PATH
cmake -S . -B build -G "MinGW Makefiles" \
  -DCMAKE_CXX_COMPILER=g++ -DCMAKE_MAKE_PROGRAM=mingw32-make
cmake --build build
```

CMake auto-hints `OPENSSL_ROOT_DIR` at the MinGW `opt` prefix. For a different OpenSSL, point it
elsewhere with `-DOPENSSL_ROOT_DIR=<path>`. The only thing it links is `libcrypto`.

## Test

The test binaries need `libcrypto-3-x64.dll` (in `.../opt/bin`) and the g++ runtime DLLs (in
`.../bin`) on your `PATH`:

```sh
export PATH="/c/ProgramData/mingw64/mingw64/opt/bin:/c/ProgramData/mingw64/mingw64/bin:$PATH"
ctest --test-dir build --output-on-failure
```

The capture itself isn't in the repo, so a clean clone runs `test_aead` and skips the other two.

- `test_frame` reads the real capture and checks every invariant from `PROVENANCE.md`. That's
  204,617 checks in total, covering 16,797 datagrams, the 8904/7893 direction split, the constant
  fields, 25 epochs, and counter monotonicity. To run it on your own capture, pass it as
  `build/test_frame.exe <path.hex>`.
- `test_aead` does a synthetic-key encrypt then decrypt round-trip for both AES-256-GCM and
  ChaCha20-Poly1305, a byte check on the nonce layout, and a rejection check for a tampered packet
  or a wrong counter.
- `test_roundtrip` shows the framing loses nothing. `serialize(parse(p)) == p` holds
  byte-for-byte across all 16,797 captured payloads, so a dropped field can't quietly come back on
  serialize.

## Layout

```
include/rbxraknet/   datagram, aead, session, packet_registry, decoder  (headers)
src/                 one .cpp per header
tests/               test_frame, test_aead, test_roundtrip, support.hpp (assert harness)
```

| Class | Role |
|---|---|
| `Datagram` | immutable view over one payload; `parse()` returns `expected<Datagram, FrameError>`; exposes flag, direction, header_len, epoch_tag, mux_extra, ciphertext, counter_hint, tag |
| `Session` | stateful core the reference lacks: reconstructs the 64-bit nonce counter from the 16-bit wire hint, detects epoch (re-key) boundaries, holds per-direction keys |
| `AeadCodec` | RAII OpenSSL EVP wrapper; both AEAD suites; `decrypt`/`encrypt`; nonce = LE u64(counter) `\|\|` suffix |
| `PacketRegistry` | id to name and metadata, each marked verified or a guess, plus the `InnerParser` interface (not implemented yet) |
| `Decoder` | orchestration: payload to `Datagram` to `Session` to decrypt (if keyed) to optional inner parse |

## Extend

To add a packet id or fix a wrong one, edit the tables in `src/packet_registry.cpp`. Only set
`Verification::verified` once a decrypted plaintext actually confirms it, not on a hunch.

Plugging in a recovered session key looks like this:

```cpp
rbxraknet::Decoder decoder(rbxraknet::CipherAlgorithm::aes_256_gcm);
decoder.session().set_key(rbxraknet::Direction::d1f, key32);  // std::array<std::byte,32>
auto result = decoder.decode(payload);                        // -> DecodeStatus::decrypted
```

If the bodies won't authenticate, there are only three knobs left to try. The algorithm
(`CipherAlgorithm`), the nonce suffix (the `AeadCodec` ctor, default `"mbeR"`), and the counter
source (`Session::observe`, which produces `full_counter`). Leave the EVP mechanics alone,
`test_aead` already proves that part.

To build the inner RakNet layer, subclass `InnerParser`, decode the reliability and message
framing out of the now-visible plaintext, lean on `PacketRegistry` to name the ids, and hand your
instance to the `Decoder` constructor.
