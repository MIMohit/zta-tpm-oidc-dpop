#!/usr/bin/env python3
"""Boot Ubuntu noble arm64 kernel+initrd under QEMU TCG + EDK2 + swtpm; dump the TCG event log and sysfs PCRs over serial.
usage: capture_evlog.py <labdir> <Image> <initrd> <outprefix> [extra-kernel-args]"""
import os, re, socket, subprocess, sys, time
lab, image, initrd, out = sys.argv[1:5]; extra = sys.argv[5] if len(sys.argv) > 5 else ""
share = subprocess.check_output(["brew", "--prefix", "qemu"], text=True).strip() + "/share/qemu"
sock_dir = "/tmp/ztamac"; os.makedirs(sock_dir, exist_ok=True)
TPMSOCK = f"{sock_dir}/swtpm.sock"
if os.path.exists(TPMSOCK): os.unlink(TPMSOCK)
os.makedirs(f"{lab}/tpm", exist_ok=True)
subprocess.run(["cp", f"{share}/edk2-arm-vars.fd", f"{lab}/vars.fd"], check=True)
open(f"{out}.raw", "wb").write(bytes(1 << 20))
swtpm = subprocess.Popen(["swtpm", "socket", "--tpmstate", f"dir={lab}/tpm", "--ctrl", f"type=unixio,path={TPMSOCK}",
                          "--tpm2", "--flags", "startup-clear", "--log", f"file={lab}/swtpm.log,level=1"])
for _ in range(50):
    if os.path.exists(TPMSOCK): break
    time.sleep(0.1)
PORT = 45123
qemu = subprocess.Popen(["qemu-system-aarch64", "-M", "virt", "-accel", "tcg,thread=multi", "-cpu", "max", "-smp", "2", "-m", "1024",
    "-drive", f"if=pflash,format=raw,readonly=on,file={share}/edk2-aarch64-code.fd",
    "-drive", f"if=pflash,format=raw,file={lab}/vars.fd",
    "-kernel", image, "-initrd", initrd, "-append", f"console=ttyAMA0 rdinit=/bin/sh {extra}",
    "-chardev", f"socket,id=chrtpm,path={TPMSOCK}", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
    "-device", "tpm-tis-device,tpmdev=tpm0", "-serial", f"tcp:127.0.0.1:{PORT},server,wait=off",
    "-drive", f"file={out}.raw,format=raw,if=virtio", "-display", "none", "-monitor", "none", "-net", "none"], stdout=open(f"{lab}/qemu.out", "w"), stderr=subprocess.STDOUT)
s = None
for _ in range(100):
    try:
        s = socket.create_connection(("127.0.0.1", PORT)); break
    except OSError: time.sleep(0.2)
s.settimeout(1.0); con = open(f"{out}.console.log", "wb"); buf = b""
def read_until(pat, timeout):
    global buf
    end = time.time() + timeout
    while time.time() < end:
        try:
            d = s.recv(65536)
            if d: buf += d; con.write(d); con.flush()
        except socket.timeout: pass
        m = re.search(pat, buf)
        if m:
            o = buf[:m.end()]; buf = buf[m.end():]; return o
    raise TimeoutError(pat)
def sh(cmd, timeout=120):
    mk = f"__E{int(time.time()*1000)}__"
    s.sendall((cmd + f"; echo {mk}\n").encode())
    o = read_until(re.escape(mk).encode() + rb"\r?\n", timeout).decode(errors="replace")
    return o.split("\n", 1)[1].replace(mk, "").strip() if "\n" in o else ""
try:
    read_until(rb"built-in shell", 900); time.sleep(2); s.sendall(b"\n"); time.sleep(1)
    sh("stty -echo 2>/dev/null; mkdir -p /proc /sys /dev; mount -t devtmpfs dev /dev 2>/dev/null; mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t securityfs none /sys/kernel/security; true")
    print(sh("ls /sys/kernel/security/tpm0/ /sys/class/tpm/tpm0/ 2>&1"))
    print(sh("ls /bin /sbin /usr/bin 2>/dev/null | tr '\\n' ' '")); print(sh("cat /sys/kernel/security/tpm0/binary_bios_measurements > /dev/vda; sync; echo copied"))
    F = "/sys/kernel/security/tpm0/binary_bios_measurements"
    HEXFMT = "'1/1 \"%02x\"'"
    hx = sh("(busybox od -An -tx1 -v " + F + " || busybox hexdump -v -e " + HEXFMT + " " + F + ") 2>&1 | tr -d ' \\n'", 300)
    hx = re.sub(r"[^0-9a-f]", "", hx)
    print("hex-bytes", len(hx) // 2)
    sh("true"); pcrs = sh("for i in 0 1 2 3 4 5 6 7; do echo $i $(cat /sys/class/tpm/tpm0/pcr-sha256/$i); done 2>&1")
    open(f"{out}.pcrs-sha256.txt", "w").write(pcrs + "\n"); print(pcrs)
    print(sh("cat /proc/version; uname -m"))
finally:
    try: s.sendall(b"echo o > /proc/sysrq-trigger\n"); time.sleep(2)
    except Exception: pass
    qemu.terminate(); swtpm.terminate(); time.sleep(1); qemu.kill(); swtpm.kill()
