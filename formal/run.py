#!/usr/bin/env python3
"""
formal/run.py - Generates the ProVerif model for the full design and for each single-mechanism
variant (formal/zta.pv.in), runs ProVerif on each, and writes formal/results/results.json.

  python3 formal/run.py [--proverif PATH] [--variants full,M3,...]

A query proved true holds for every attacker in the model; "false" means ProVerif found an
attack trace (written to formal/results/<variant>.out).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VARIANTS = ["full", "M3", "M4", "M6", "M8", "M10", "M12", "M16", "M17"]
QUERIES = [
    ("boot", "G1 boot state", "Appraised(d, n) ⇒ DeviceGood(d)"),
    ("fresh", "G1 freshness and AK binding", "Appraised(d, n) ⇒ TPMQuoted(d, n)"),
    ("bind", "G2 attested key binding", "Issued(u, d, j) ⇒ TPMHoldsKB(d, j) ∧ Enrolled(d, j, u)"),
    ("sender", "G3 sender constraint (injective)", "inj Accepted(u, d, j, r, n) ⇒ inj TPMSignedProof(j, r, n)"),
    ("sanity", "Honest flow executable", "Accepted reachable (expected: false)"),
]


def generate(variant):
    out = []
    for line in (HERE / "zta.pv.in").read_text().splitlines():
        m = re.search(r"\(\*@(M\d+)([+-])\*\)", line)
        if m:
            mech, sign = m.groups()
            keep = (variant != mech) if sign == "+" else (variant == mech)
            if not keep:
                continue
            line = line[: m.start()].rstrip()
        out.append(line)
    return "\n".join(out) + "\n"


def run(proverif, variant, outdir):
    model = outdir / f"zta-{variant}.pv"
    model.write_text(generate(variant))
    t0 = time.time()
    res = subprocess.run([proverif, str(model)], capture_output=True, text=True, timeout=3600)
    (outdir / f"zta-{variant}.out").write_text(res.stdout + res.stderr)
    if res.returncode != 0 and "RESULT" not in res.stdout:
        raise SystemExit(f"ProVerif failed on {variant}:\n{res.stdout[-2000:]}{res.stderr[-2000:]}")
    results = re.findall(r"^RESULT (.*) is (true|false|cannot be proved)\.?$", res.stdout, re.M)
    if len(results) != len(QUERIES):
        raise SystemExit(f"{variant}: expected {len(QUERIES)} results, got {len(results)}:\n{res.stdout[-3000:]}")
    return {key: verdict for (key, _, _), (_, verdict) in zip(QUERIES, results)}, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proverif", default=os.environ.get("PROVERIF") or shutil.which("proverif"))
    ap.add_argument("--variants", default=",".join(VARIANTS))
    a = ap.parse_args()
    if not a.proverif:
        raise SystemExit("proverif not found: pass --proverif or set PROVERIF")
    outdir = HERE / "results"
    outdir.mkdir(exist_ok=True)
    ver = subprocess.run([a.proverif, "-help"], capture_output=True, text=True).stdout.splitlines()[0]
    rows = {}
    for v in a.variants.split(","):
        verdicts, secs = run(a.proverif, v, outdir)
        rows[v] = {"verdicts": verdicts, "seconds": round(secs, 2)}
        print(f"{v:5s} " + "  ".join(f"{k}={verdicts[k]}" for k, _, _ in QUERIES) + f"  ({secs:.1f} s)")
    (outdir / "results.json").write_text(json.dumps({"proverif": ver, "queries": QUERIES, "variants": rows}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
