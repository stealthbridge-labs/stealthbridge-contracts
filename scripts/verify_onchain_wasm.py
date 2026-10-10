#!/usr/bin/env python3
"""Read-only comparison of locally built WASM against real Testnet contract instances.

Requires operator-supplied deployed C-addresses. Uses Stellar CLI 'contract
fetch' only. Does not sign, submit, simulate payments or claim owner attestation.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from validate_manifest import contract_id
from verify_artifacts import CONTRACT_FILES, verify


def validate_contract_ids(ids):
    if not isinstance(ids, dict) or set(ids) != set(CONTRACT_FILES):
        raise ValueError("All three named Soroban contract IDs are required")
    if not all(contract_id(value) for value in ids.values()):
        raise ValueError("Invalid Soroban contract StrKey checksum or type")
    if len(set(ids.values())) != 3:
        raise ValueError("Contract ID bindings must be unique")
    return ids


def fetch_testnet_wasm(contract_address, *, cli="stellar"):
    # The signer-independent read is deliberately limited to the known CLI
    # command; no shell, user-controlled flags, or secret-bearing RPC URL.
    with tempfile.TemporaryDirectory(prefix="stealthbridge-chain-proof-") as name:
        destination = Path(name) / "verified.wasm"
        try:
            subprocess.run(
                [cli, "contract", "fetch", "--id", contract_address,
                 "--network", "testnet", "--out-file", str(destination)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=45,
            )
        except (OSError, subprocess.SubprocessError):
            raise ValueError("Unable to fetch actual contract bytecode on Testnet") from None
        data = destination.read_bytes()
        if not data or len(data) > 2_000_000:
            raise ValueError("On-chain WASM size outside approved bounds")
        return data


def compare_artifacts(root, contract_ids, *, fetcher=fetch_testnet_wasm):
    if verify(root) != 3:
        raise ValueError("Missing verified local artifacts")
    ids = validate_contract_ids(contract_ids)
    provenance = json.loads((Path(root) / "provenance.json").read_text())
    observed = {}
    for name, (file, _) in CONTRACT_FILES.items():
        actual = fetcher(ids[name])
        if not isinstance(actual, bytes) or not actual or len(actual) > 2_000_000:
            raise ValueError(f"Invalid on-chain bytecode for {name}")
        digest = hashlib.sha256(actual).hexdigest()
        expected = provenance["contractArtifacts"][name]["wasmSha256"]
        if digest != expected or actual != (Path(root) / file).read_bytes():
            raise ValueError(f"On-chain WASM differs from the reproducible build for {name}")
        observed[name] = {"wasm_sha256": digest, "bytecode_matches": True}
    return {"network_target": "testnet", "bytecode_matches": observed,
            "admin_verified": False, "constructor_bindings_verified": False,
            "payment_execution_enabled": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts-file", type=Path, required=True,
                        help="Local JSON map of real, operator-reviewed C-addresses")
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    try:
        ids = json.loads(args.contracts_file.read_text())
        result = compare_artifacts(args.artifacts, ids)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("On-chain WASM verification failed. Check actual deployed IDs, "
              "network configuration and pinned artifact hashes.", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
