#!/usr/bin/env python3
"""Fail if the forgeable Groth16 smoke-test setup can leak into real use.

The pairing smoke test derives Groth16 toxic waste from public SHA-256 labels
(audit C-2): anyone can forge proofs for its key. This guard checks that:
1. the generator exists only at its quarantined example path;
2. that example builds only behind the explicit `forgeable-test-setup` feature;
3. no source outside tests/examples uses its toxic-waste labels;
4. the deployment record labels the instance as a forgeable smoke test.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUARANTINED = ROOT / "contracts/privacy-verifier/examples/pairing_smoke_test_forgeable_key.rs"
MARKER = "PAIRING SMOKE TEST ONLY. NOT A ZERO-KNOWLEDGE PROOF SYSTEM."
SKIP = ("target", "node_modules", ".git", "test_snapshots")


def fail(message):
    print(f"forgeable-key quarantine FAILED: {message}")
    sys.exit(1)


def feature_gated(path):
    """True when the module is declared only behind `forgeable-test-setup` in its lib.rs."""
    lib = path.parent / "lib.rs"
    if not lib.exists() or path.name == "lib.rs":
        return False
    pattern = r'#\[cfg\(feature = "forgeable-test-setup"\)\]\s*pub mod ' + re.escape(path.stem) + r";"
    return re.search(pattern, re.sub(r"\n\s*///[^\n]*", "", lib.read_text())) is not None


def main():
    if not QUARANTINED.exists() or MARKER not in QUARANTINED.read_text():
        fail("the quarantined generator or its warning header is missing")
    cargo = (ROOT / "contracts/privacy-verifier/Cargo.toml").read_text()
    if not re.search(r'\[\[example\]\]\s*name = "pairing_smoke_test_forgeable_key".*?required-features = \["forgeable-test-setup"\]', cargo, re.S):
        fail("the generator example must require the forgeable-test-setup feature")
    for path in ROOT.rglob("*.rs"):
        if any(part in SKIP for part in path.parts) or path == QUARANTINED:
            continue
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(errors="ignore")
        if MARKER in text:
            fail(f"a copy of the forgeable generator exists at {rel}")
        is_test = "/tests/" in f"/{rel}" or rel.endswith("test.rs") or "/examples/" in f"/{rel}"
        if not is_test and re.search(r"fn hash_to_fr\(|toxic waste", text, re.I) and not feature_gated(path):
            fail(f"SHA-derived setup code outside tests/examples and not feature-gated: {rel}")
    record = json.loads((ROOT / "deployments/testnet/protocol-deployment.v3.json").read_text())
    pv = record["protocolContracts"]["privacy-verifier"]
    if pv.get("registeredKeyClass") != "forgeable-test-setup" or pv.get("realPrivacyProof") is not False:
        fail("the Testnet privacy-verifier record must say its key is a forgeable test setup")
    print("forgeable-key quarantine OK")


if __name__ == "__main__":
    main()
