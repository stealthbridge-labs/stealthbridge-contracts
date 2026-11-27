#!/usr/bin/env python3
"""Verify the canonical privacy dependency lock (integrations/privacy-dependency-lock.v2.json).

Offline (default, CI): structure, hash formats, StrKey checksums, and a
fail-closed verdict: a rail can never be GO while it records blockers, a
single-party ("local") trusted setup, or an unaudited upstream.

    python3 scripts/verify_privacy_dependency_lock.py            # offline
    python3 scripts/verify_privacy_dependency_lock.py --live     # + fetch each Testnet WASM and compare
    python3 scripts/verify_privacy_dependency_lock.py --sources  # + re-hash pinned upstream source blobs

Read-only: uses `stellar contract fetch` and public GitHub reads only.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "integrations/privacy-dependency-lock.v2.json"
RAILS = ("personal-shielded-pool", "business-confidential-token")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def require(cond, message):
    if not cond:
        raise ValueError(message)


def contract_id(value):
    """True for a checksummed C… StrKey."""
    if not isinstance(value, str) or not re.fullmatch(r"C[A-Z2-7]{55}", value):
        return False
    bits = acc = 0
    out = bytearray()
    for ch in value:
        acc = (acc << 5) | B32.index(ch)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 255)
            acc &= (1 << bits) - 1
    if len(out) != 35 or out[0] != 2 << 3:
        return False
    crc = 0
    for b in out[:33]:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return out[33] == crc & 255 and out[34] == crc >> 8


def validate(lock):
    require(isinstance(lock, dict) and lock.get("schemaVersion") == 2 and lock.get("canonical") is True,
            "not the canonical v2 privacy lock")
    require(lock.get("network") == "testnet" and lock.get("networkPassphrase") == "Test SDF Network ; September 2015",
            "privacy lock must target Stellar Testnet only")
    rails = lock.get("rails")
    require(isinstance(rails, dict) and set(rails) == set(RAILS), "exactly the Personal and Business rails")
    for name in RAILS:
        rail = rails[name]
        blockers = rail.get("blockers")
        require(isinstance(blockers, list) and all(isinstance(b, str) and len(b) > 10 for b in blockers),
                f"{name}: blockers must be listed")
        crypto = rail.get("cryptography", {})
        audit = rail.get("audit", {}).get("status")
        require(audit in ("unaudited", "audited-at-snapshot", "audited"), f"{name}: unknown audit status")
        verdict = rail.get("verdict")
        require(verdict in ("NO_GO", "GO"), f"{name}: verdict must be NO_GO or GO")
        if verdict == "GO":
            require(not blockers, f"{name}: GO with open blockers")
            require(crypto.get("trustedSetup") != "local", f"{name}: GO with a single-party trusted setup")
            require(audit != "unaudited", f"{name}: GO while unaudited")
        for path, blob in rail.get("upstream", {}).get("sourceBlobs", {}).items():
            require(isinstance(path, str) and SHA1.match(blob or ""), f"{name}: bad source blob for {path}")
        for c in rail.get("testnetDeployment", {}).get("contracts", []):
            require(contract_id(c.get("id")), f"{name}: invalid contract id {c.get('id')}")
            require(SHA256.match(c.get("wasmSha256", "")), f"{name}: bad wasm hash for {c.get('id')}")
            require(isinstance(c.get("wasmBytes"), int) and 0 < c["wasmBytes"] < 2_000_000,
                    f"{name}: bad wasm size for {c.get('id')}")
    personal = rails["personal-shielded-pool"]
    require(personal["cryptography"]["proofSystem"] == "Groth16" and personal["cryptography"]["curve"] == "BN254",
            "personal rail must be the pinned Groth16/BN254 pool")
    for stem, arts in personal["cryptography"].get("circuitArtifacts", {}).items():
        for kind, digest in arts.items():
            require(SHA256.match(digest), f"bad circuit artifact hash {stem}/{kind}")
    business = rails["business-confidential-token"]
    require("UltraHonk" in business["cryptography"]["proofSystem"], "business rail must be the pinned UltraHonk token")
    require(business["clientSdk"].get("official", "").startswith("none"),
            "an official confidential client must be pinned explicitly before it is claimed")
    return lock


def fetch_wasm(contract, cli="stellar"):
    with tempfile.TemporaryDirectory(prefix="sb-privacy-lock-") as d:
        out = Path(d) / "c.wasm"
        subprocess.run([cli, "contract", "fetch", "--id", contract, "--network", "testnet", "--out-file", str(out)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
        return out.read_bytes()


def check_live(lock, fetcher=fetch_wasm):
    results = []
    for name in RAILS:
        for c in lock["rails"][name].get("testnetDeployment", {}).get("contracts", []):
            data = fetcher(c["id"])
            digest = hashlib.sha256(data).hexdigest()
            require(digest == c["wasmSha256"] and len(data) == c["wasmBytes"],
                    f"{name}: on-chain WASM for {c['id']} is {digest} ({len(data)} B), lock says {c['wasmSha256']}")
            results.append((c["id"], digest))
    return results


def github_blob_sha(repo, commit, path):
    url = f"https://api.github.com/repos/{repo}/contents/{path}?ref={commit}"
    with urlopen(Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "stealthbridge-lock-check"}), timeout=30) as r:
        return json.load(r)["sha"]


def check_sources(lock, blob=github_blob_sha):
    count = 0
    for name in RAILS:
        up = lock["rails"][name]["upstream"]
        commit = up.get("deploymentCommit") or up.get("commit")
        for path, expected in up.get("sourceBlobs", {}).items():
            require(blob(up["repository"], commit, path) == expected, f"{name}: source blob drift at {path}")
            count += 1
    return count


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--sources", action="store_true")
    args = ap.parse_args()
    try:
        lock = validate(json.loads(LOCK.read_text()))
        print(f"privacy lock OK: {', '.join(f'{r}={lock['rails'][r]['verdict']}' for r in RAILS)}")
        if args.live:
            print(f"live Testnet WASM matches for {len(check_live(lock))} contracts")
        if args.sources:
            print(f"upstream source blobs match: {check_sources(lock)}")
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, json.JSONDecodeError) as e:
        print(f"privacy lock verification FAILED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
