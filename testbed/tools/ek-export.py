#!/usr/bin/env python3
"""Raw TPM2 commands over swtpm TCP data channel:
Read and export EK certificates from NV indices, public areas from persistent handles,
compute RFC 7638 SHA-256 devId thumbprints, and write standard export files.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <port> <outdir>")
        sys.exit(1)

    host = "127.0.0.1"
    port = int(sys.argv[1])
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    s = socket.create_connection((host, port))

    def cmd(cc, body=b"", tag=0x8001):
        pkt = struct.pack(">HII", tag, 10 + len(body), cc) + body
        s.sendall(pkt)
        hdr = b""
        while len(hdr) < 10:
            hdr += s.recv(10 - len(hdr))
        t, sz, rc = struct.unpack(">HII", hdr)
        rest = b""
        while len(rest) < sz - 10:
            rest += s.recv(sz - 10 - len(rest))
        return rc, rest

    def caps(first):
        rc, r = cmd(0x17A, struct.pack(">III", 1, first, 64))  # TPM2_GetCapability(TPM_CAP_HANDLES)
        if rc != 0:
            return []
        cnt, = struct.unpack_from(">I", r, 5)
        return [struct.unpack_from(">I", r, 9 + 4 * i)[0] for i in range(cnt)]

    def b64url(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    def thumbprint(jwk):
        canonical = json.dumps(jwk, separators=(",", ":"), sort_keys=True)
        return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())

    def parse_pub(b):
        o = 0
        typ, nalg, attrs = struct.unpack_from(">HHI", b, o)
        o += 8
        pl, = struct.unpack_from(">H", b, o)
        o += 2 + pl
        sym, = struct.unpack_from(">H", b, o)
        o += 2
        if sym != 0x10:
            o += 4
        sch, = struct.unpack_from(">H", b, o)
        o += 2
        if typ == 0x23:  # ECC
            if sch != 0x10:
                o += 2
            cur, kdf = struct.unpack_from(">HH", b, o)
            o += 4
            xl, = struct.unpack_from(">H", b, o)
            o += 2
            x = b[o:o + xl]
            o += xl
            yl, = struct.unpack_from(">H", b, o)
            o += 2
            y = b[o:o + yl]
            o += yl
            crv_name = "P-256" if cur == 3 else ("P-384" if cur == 4 else str(cur))
            jwk = {"kty": "EC", "crv": crv_name, "x": b64url(x), "y": b64url(y)}
            return {"type": "ecc", "curve": crv_name, "jwk": jwk, "devId": thumbprint(jwk)}
        elif typ == 0x01:  # RSA
            kbits, exp = struct.unpack_from(">HI", b, o)
            o += 6
            if exp == 0:
                exp = 65537
            exp_bytes = exp.to_bytes((exp.bit_length() + 7) // 8, "big")
            nl, = struct.unpack_from(">H", b, o)
            o += 2
            n = b[o:o + nl]
            jwk = {"kty": "RSA", "n": b64url(n), "e": b64url(exp_bytes)}
            return {"type": "rsa", "keyBits": kbits, "jwk": jwk, "devId": thumbprint(jwk)}
        return {"type": "unknown"}

    def nv_read(h, size):
        out = b""
        while len(out) < size:
            n = min(1024, size - len(out))
            auth = struct.pack(">IHBH", 0x40000009, 0, 0, 0)  # TPM_RS_PW
            body = struct.pack(">II", h, h) + struct.pack(">I", len(auth)) + auth + struct.pack(">HH", n, len(out))
            rc, r = cmd(0x14E, body, tag=0x8002)
            if rc:
                raise RuntimeError(f"NV_Read {hex(h)} failed with rc {hex(rc)}")
            ln, = struct.unpack_from(">H", r, 4)
            out += r[6:6 + ln]
        return out

    def get_der_length(b):
        if len(b) < 2 or b[0] != 0x30:
            return len(b)
        if b[1] < 0x80:
            return 2 + b[1]
        num_len_bytes = b[1] & 0x7F
        if len(b) < 2 + num_len_bytes:
            return len(b)
        length = int.from_bytes(b[2:2 + num_len_bytes], "big")
        return 2 + num_len_bytes + length

    def to_pem(der_bytes, label="CERTIFICATE"):
        b64 = base64.b64encode(der_bytes).decode("ascii")
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"

    # Startup if needed
    cmd(0x144, struct.pack(">H", 0))

    nv_handles = caps(0x01000000)
    per_handles = caps(0x81000000)

    nv_lines = []
    for h in nv_handles:
        rc, r = cmd(0x169, struct.pack(">I", h))  # NV_ReadPublic
        if rc:
            continue
        sz, = struct.unpack_from(">H", r, 0)
        nvp = r[2:2 + sz]
        idx, nalg, attrs = struct.unpack_from(">IHI", nvp, 0)
        pl, = struct.unpack_from(">H", nvp, 10)
        dsz, = struct.unpack_from(">H", nvp, 12 + pl)
        nv_lines.append(f"0x{h:08x} nvAttrs=0x{attrs:08x} dataSize={dsz}")

        data = nv_read(h, dsz)
        der_len = get_der_length(data)
        trimmed = data[:der_len]

        with open(os.path.join(outdir, f"nv-{h:08x}.der"), "wb") as f:
            f.write(trimmed)
        with open(os.path.join(outdir, f"nv-{h:08x}.pem"), "w") as f:
            f.write(to_pem(trimmed))

        if h == 0x01C00002:
            with open(os.path.join(outdir, "ekcert-rsa2048.der"), "wb") as f:
                f.write(trimmed)
            with open(os.path.join(outdir, "ekcert-rsa2048-nv01c00002.der"), "wb") as f:
                f.write(trimmed)
            with open(os.path.join(outdir, "ekcert-rsa2048.pem"), "w") as f:
                f.write(to_pem(trimmed))
        elif h == 0x01C00016:
            with open(os.path.join(outdir, "ekcert-p384.der"), "wb") as f:
                f.write(trimmed)
            with open(os.path.join(outdir, "ekcert-p384-nv01c00016.der"), "wb") as f:
                f.write(trimmed)
            with open(os.path.join(outdir, "ekcert-p384.pem"), "w") as f:
                f.write(to_pem(trimmed))
        elif h == 0x01C08000:
            with open(os.path.join(outdir, "platformcert.der"), "wb") as f:
                f.write(trimmed)
            with open(os.path.join(outdir, "platformcert-nv01c08000.der"), "wb") as f:
                f.write(trimmed)
            with open(os.path.join(outdir, "platformcert.pem"), "w") as f:
                f.write(to_pem(trimmed))

    per_lines = []
    devids = {}
    for h in per_handles:
        rc, r = cmd(0x173, struct.pack(">I", h))  # ReadPublic
        if rc:
            continue
        sz, = struct.unpack_from(">H", r, 0)
        tpmt = r[2:2 + sz]
        with open(os.path.join(outdir, f"pub-{h:08x}.tpmt"), "wb") as f:
            f.write(tpmt)

        info = parse_pub(tpmt)
        per_lines.append(f"0x{h:08x} type={info.get('type')}")

        if h == 0x81010001:
            with open(os.path.join(outdir, "ek-rsa2048.tpmt"), "wb") as f:
                f.write(tpmt)
            if "devId" in info:
                devids["rsa2048"] = info["devId"]
                with open(os.path.join(outdir, "devid-rsa2048.txt"), "w") as f:
                    f.write(info["devId"] + "\n")
        elif h == 0x81010016:
            with open(os.path.join(outdir, "ek-p384.tpmt"), "wb") as f:
                f.write(tpmt)
            if "devId" in info:
                devids["p384"] = info["devId"]
                with open(os.path.join(outdir, "devid-p384.txt"), "w") as f:
                    f.write(info["devId"] + "\n")

    # Set default devid.txt (p384 preferred for vTPM fleet, else rsa2048)
    if "p384" in devids:
        with open(os.path.join(outdir, "devid.txt"), "w") as f:
            f.write(devids["p384"] + "\n")
    elif "rsa2048" in devids:
        with open(os.path.join(outdir, "devid.txt"), "w") as f:
            f.write(devids["rsa2048"] + "\n")

    # Write nv-index.txt listing handles
    with open(os.path.join(outdir, "nv-index.txt"), "w") as f:
        f.write("NV indices:\n")
        for line in nv_lines:
            f.write(f"  {line}\n")
        f.write("Persistent handles:\n")
        for line in per_lines:
            f.write(f"  {line}\n")

    print(f"Exported {len(nv_handles)} NV areas and {len(per_handles)} persistent handles to {outdir}")

if __name__ == "__main__":
    main()
