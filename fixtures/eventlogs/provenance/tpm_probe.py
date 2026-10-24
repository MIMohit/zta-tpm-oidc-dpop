#!/usr/bin/env python3
"""Raw TPM2 commands over swtpm TCP data channel: list NV + persistent handles, dump public areas."""
import socket, struct, sys, hashlib, json
host, port = "127.0.0.1", int(sys.argv[1])
s = socket.create_connection((host, port))
def cmd(cc, body=b"", tag=0x8001):
    pkt = struct.pack(">HII", tag, 10 + len(body), cc) + body
    s.sendall(pkt); hdr = b""
    while len(hdr) < 10: hdr += s.recv(10 - len(hdr))
    t, sz, rc = struct.unpack(">HII", hdr); rest = b""
    while len(rest) < sz - 10: rest += s.recv(sz - 10 - len(rest))
    return rc, rest
def caps(first):
    rc, r = cmd(0x17A, struct.pack(">III", 1, first, 64))  # TPM2_GetCapability(TPM_CAP_HANDLES)
    cnt, = struct.unpack_from(">I", r, 5); return [struct.unpack_from(">I", r, 9 + 4 * i)[0] for i in range(cnt)]
def parse_pub(b):
    o = 0; typ, nalg, attrs = struct.unpack_from(">HHI", b, o); o += 8
    pl, = struct.unpack_from(">H", b, o); o += 2; pol = b[o:o + pl]; o += pl
    d = {"type": hex(typ), "nameAlg": hex(nalg), "attrs": hex(attrs), "authPolicy": pol.hex()}
    sym, = struct.unpack_from(">H", b, o); o += 2
    if sym != 0x10: kb, mode = struct.unpack_from(">HH", b, o); o += 4; d["sym"] = [hex(sym), kb, hex(mode)]
    sch, = struct.unpack_from(">H", b, o); o += 2; d["scheme"] = hex(sch)
    if typ == 0x23:
        if sch != 0x10: o += 2
        cur, kdf = struct.unpack_from(">HH", b, o); o += 4; d["curve"] = hex(cur)
        xl, = struct.unpack_from(">H", b, o); d["xlen"] = xl
    elif typ == 0x1:
        kbits, exp = struct.unpack_from(">HI", b, o); d["keyBits"] = kbits; d["exp"] = exp
    return d
print("startup rc", hex(cmd(0x144, struct.pack(">H", 0))[0]))
nv = caps(0x01000000); per = caps(0x81000000)
print("NV", [hex(h) for h in nv]); print("persistent", [hex(h) for h in per])
for h in nv:
    rc, r = cmd(0x169, struct.pack(">I", h))  # NV_ReadPublic
    if rc: print(hex(h), "rc", hex(rc)); continue
    sz, = struct.unpack_from(">H", r, 0); nvp = r[2:2 + sz]
    idx, nalg, attrs, = struct.unpack_from(">IHI", nvp, 0); pl, = struct.unpack_from(">H", nvp, 10); dsz, = struct.unpack_from(">H", nvp, 12 + pl)
    print(hex(h), "nvAttrs", hex(attrs), "dataSize", dsz)
for h in per:
    rc, r = cmd(0x173, struct.pack(">I", h))  # ReadPublic
    sz, = struct.unpack_from(">H", r, 0); print(hex(h), json.dumps(parse_pub(r[2:2 + sz])))
def nv_read(h, size):
    out = b""
    while len(out) < size:
        n = min(1024, size - len(out))
        auth = struct.pack(">IHBH", 0x40000009, 0, 0, 0)  # TPM_RS_PW, empty nonce, attrs, empty hmac
        body = struct.pack(">II", h, h) + struct.pack(">I", len(auth)) + auth + struct.pack(">HH", n, len(out))
        rc, r = cmd(0x14E, body, tag=0x8002)
        if rc: raise SystemExit(f"NV_Read {hex(h)} rc {hex(rc)}")
        ln, = struct.unpack_from(">H", r, 4); out += r[6:6 + ln]
    return out
import os
outdir = sys.argv[2] if len(sys.argv) > 2 else None
if outdir:
    for h in nv:
        rc, r = cmd(0x169, struct.pack(">I", h)); sz, = struct.unpack_from(">H", r, 0); nvp = r[2:2 + sz]
        pl, = struct.unpack_from(">H", nvp, 10); dsz, = struct.unpack_from(">H", nvp, 12 + pl)
        data = nv_read(h, dsz); der_len = 4 + struct.unpack(">H", data[2:4])[0] if data[1] == 0x82 else None
        print(hex(h), "nvsize", dsz, "der_len", der_len, "trailing_nonzero", any(data[der_len:]) if der_len else None)
        open(os.path.join(outdir, f"nv-{h:08x}.der"), "wb").write(data[:der_len] if der_len else data)
    for h in per:
        rc, r = cmd(0x173, struct.pack(">I", h)); sz, = struct.unpack_from(">H", r, 0)
        open(os.path.join(outdir, f"pub-{h:08x}.tpmt"), "wb").write(r[2:2 + sz])
