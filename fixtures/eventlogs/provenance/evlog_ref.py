#!/usr/bin/env python3
"""Independent reference parser for TCG PC Client crypto-agile event logs (cross-check for lib/verifier/tcg-eventlog.js)."""
import hashlib, json, struct, sys
ALG = {0x0004: ("sha1", 20), 0x000b: ("sha256", 32), 0x000c: ("sha384", 48), 0x000d: ("sha512", 64), 0x0012: ("sm3_256", 32)}
def parse(buf):
    o = 0
    pcr, etype = struct.unpack_from("<II", buf, o); o += 8
    o += 20  # SHA1 digest of legacy header
    esz, = struct.unpack_from("<I", buf, o); o += 4
    spec = buf[o:o + esz]; o += esz
    hdr = {"pcr": pcr, "type": etype, "sig": spec[:16].rstrip(b"\0").decode(errors="replace")}
    if etype != 3 or not spec.startswith(b"Spec ID Event03"):
        return {"header": hdr, "agile": False}
    so = 16 + 4 + 4  # sig, platformClass, specVersion minor/major/errata/uintnSize
    nalg, = struct.unpack_from("<I", spec, so); so += 4
    sizes = {}
    for _ in range(nalg):
        a, s = struct.unpack_from("<HH", spec, so); so += 4; sizes[a] = s
    hdr["algs"] = {ALG.get(a, (hex(a),))[0]: s for a, s in sizes.items()}
    events = []
    while o < len(buf):
        if len(buf) - o < 12: break
        p, t, cnt = struct.unpack_from("<III", buf, o)
        if t == 0 and cnt == 0: break
        o += 12
        dig = {}
        for _ in range(cnt):
            a, = struct.unpack_from("<H", buf, o); o += 2
            n = sizes[a]; dig[a] = buf[o:o + n]; o += n
        ln, = struct.unpack_from("<I", buf, o); o += 4
        data = buf[o:o + ln]; o += ln
        events.append((p, t, dig, data))
    return {"header": hdr, "agile": True, "events": events, "sizes": sizes}
def replay(r, alg=0x000b):
    n = r["sizes"][alg]; pcrs = {i: bytes(n) for i in range(24)}
    loc = None
    for p, t, dig, data in r["events"]:
        if t == 0x3 and data.startswith(b"StartupLocality\0"):
            loc = data[16]; pcrs[0] = bytes(n - 1) + bytes([loc]); continue
        if t == 0x3: continue  # EV_NO_ACTION not extended
        if alg in dig and p < 24:
            pcrs[p] = hashlib.new(ALG[alg][0], pcrs[p] + dig[alg]).digest()
    return pcrs, loc
for f in sys.argv[1:]:
    b = open(f, "rb").read(); r = parse(b)
    if not r["agile"]:
        print(json.dumps({"file": f.split("/")[-1], "agile": False, "hdr": r["header"]})); continue
    ev = r["events"]; types = {}
    for p, t, d, data in ev: types[hex(t)] = types.get(hex(t), 0) + 1
    out = {"file": f.split("/")[-1], "bytes": len(b), "algs": r["header"]["algs"], "events": len(ev),
           "pcrs_used": sorted({e[0] for e in ev}), "types": types}
    if 0x000b in r["sizes"]:
        pcrs, loc = replay(r); out["startupLocality"] = loc
        out["sha256_pcr0_7"] = {i: pcrs[i].hex()[:16] for i in range(8)}
        out["sha256_quote_digest_pcr0_7"] = hashlib.sha256(b"".join(pcrs[i] for i in range(8))).hexdigest()
        # digest-vs-payload self-consistency for EV_EFI_ACTION/EV_SEPARATOR (hash of data)
        bad = [i for i, (p, t, d, data) in enumerate(ev) if t in (0x4, 0x80000007) and 0x000b in d and hashlib.sha256(data).digest() != d[0x000b]]
        out["action_sep_digest_mismatch_idx"] = bad
    print(json.dumps(out))
