#!/usr/bin/env python3
"""
scripts/sbom.py - CycloneDX 1.5 SBOM of the production dependency tree, read from package-lock.json.
(`npm sbom` refuses the vendored ffi-stub aliases that tss.js depends on.)

  python3 scripts/sbom.py > results/supply-chain/sbom.cdx.json
"""

import base64
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def purl(name, version):
    if name.startswith("@"):
        scope, pkg = name[1:].split("/", 1)
        return f"pkg:npm/%40{scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def hashes(integrity):
    out = []
    for item in (integrity or "").split():
        alg, _, b64 = item.partition("-")
        if alg in ("sha512", "sha384", "sha256", "sha1"):
            out.append({"alg": {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}[alg], "content": base64.b64decode(b64).hex()})
    return out


def main():
    pkg = json.loads((REPO / "package.json").read_text())
    lock = json.loads((REPO / "package-lock.json").read_text())
    comps = {}
    for path, meta in lock["packages"].items():
        if not path or meta.get("dev") or meta.get("link"):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        version = meta.get("version")
        if not version:
            continue
        ref = purl(name, version)
        if ref in comps:
            continue
        c = {"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref, "scope": "optional" if meta.get("optional") else "required"}
        if meta.get("license"):
            c["licenses"] = [{"expression": meta["license"]}] if " " in meta["license"] else [{"license": {"id": meta["license"]}}]
        h = hashes(meta.get("integrity"))
        if h:
            c["hashes"] = h
        if meta.get("resolved"):
            c["externalReferences"] = [{"type": "distribution", "url": meta["resolved"]}]
        comps[ref] = c
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"name": "scripts/sbom.py"}],
            "component": {"type": "application", "name": pkg.get("name") or "zta-tpm-oidc-dpop", "version": pkg.get("version") or "0.0.0"},
        },
        "components": sorted(comps.values(), key=lambda c: c["bom-ref"]),
    }
    json.dump(bom, sys.stdout, indent=2)
    print(f"{len(comps)} components", file=sys.stderr)


if __name__ == "__main__":
    main()
