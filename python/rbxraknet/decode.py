"""The command-line tool. Give it a hex capture (one UDP payload per line) and a
key for each direction and it decodes the whole thing.

    python -m rbxraknet.decode --capture cap.hex \
        --key-17 <hex> [--cipher-17 aes-256-gcm] \
        --key-1f <hex> [--cipher-1f chacha20-poly1305] [--limit N] [--span N]

For each direction it prints how much of the capture decrypted and a histogram
of the inner leading byte. If the inner decoder is around it also shows a full
structured decode of the first few packets. The 0x17 stream retransmits a lot,
so I dedupe it before building the histogram.
"""
import argparse
from collections import Counter

from .framing import parse
from .aead import AeadCodec, AES, CHACHA

try:
    from .inner import decode_inner        # nice to have, not required
except Exception:
    decode_inner = None


def _load_codecs(a):
    codecs = {}
    if a.key_17:
        codecs[0x17] = AeadCodec(bytes.fromhex(a.key_17), a.cipher_17)
    if a.key_1f:
        codecs[0x1F] = AeadCodec(bytes.fromhex(a.key_1f), a.cipher_1f)
    if not codecs:
        raise SystemExit("give at least one of --key-17 / --key-1f")
    return codecs


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True)
    ap.add_argument("--key-17")
    ap.add_argument("--cipher-17", default=AES, choices=(AES, CHACHA))
    ap.add_argument("--key-1f")
    ap.add_argument("--cipher-1f", default=AES, choices=(AES, CHACHA))
    ap.add_argument("--limit", type=int, default=0, help="max lines (0 = all)")
    ap.add_argument("--show", type=int, default=5, help="structured-decode first N distinct")
    ap.add_argument("--span", type=int, default=2,
                    help="counter windows to try per packet. 2 covers a session-start capture up "
                         "to 131072 packets/direction; raise it for longer or mid-session captures")
    a = ap.parse_args(argv)
    codecs = _load_codecs(a)

    ok = Counter()
    fail = Counter()
    leads = {d: Counter() for d in codecs}
    seen = set()
    shown = 0
    for i, line in enumerate(open(a.capture, encoding="utf-8", errors="ignore")):
        if a.limit and i >= a.limit:
            break
        line = line.strip()
        if not line:
            continue
        try:
            dg = parse(bytes.fromhex(line))
        except ValueError:
            continue
        codec = codecs.get(dg.direction)
        if codec is None:
            continue
        pt, ctr = codec.decrypt(dg, span=a.span)
        if pt is None:
            fail[dg.direction] += 1
            continue
        ok[dg.direction] += 1
        key = (dg.direction, dg.epoch_tag, ctr)
        if key in seen:
            continue
        seen.add(key)
        leads[dg.direction][pt[0]] += 1
        if decode_inner and shown < a.show:
            shown += 1
            print(f"\n0x{dg.direction:02x} counter={ctr} len={len(pt)}")
            print(f"  {decode_inner(pt)}")

    print("\n=== decode summary ===")
    for d in sorted(codecs):
        tot = ok[d] + fail[d]
        rate = (ok[d] / tot * 100) if tot else 0.0
        print(f"dir 0x{d:02x} ({codecs[d].cipher}): {ok[d]}/{tot} decrypted ({rate:.1f}%)")
        for b, n in leads[d].most_common(8):
            print(f"    inner id 0x{b:02x} : {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
