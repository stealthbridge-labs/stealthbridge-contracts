#!/usr/bin/env python3
"""Validate deployment records against local build evidence; never use the network."""
import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re

PASSPHRASE = "Test SDF Network ; September 2015"
BASE = {"schemaVersion", "network", "status", "verified", "contractAddresses", "assetIssuers", "txHashes", "notes"}
DEPLOYED = {"networkPassphrase", "sourceCommit", "sourceSha256", "wasmSha256", "abiSha256"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hex_hash(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def contract_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"C[A-Z2-7]{55}", value):
        return False
    try:
        decoded = base64.b32decode(value)
        return (len(decoded) == 35 and decoded[0] == 16
                and binascii.crc_hqx(decoded[:-2], 0).to_bytes(2, "little") == decoded[-2:])
    except (ValueError, binascii.Error):
        return False


def validate(data, evidence=None, wasm=None, abi=None):
    require(isinstance(data, dict), "manifest must be an object")
    require(BASE <= data.keys(), "missing required manifest fields")
    require(type(data["schemaVersion"]) is int and data["schemaVersion"] == 1, "unsupported schemaVersion")
    require(data["network"] == "testnet", "only testnet is supported")
    require(type(data["verified"]) is bool, "verified must be boolean")
    require(isinstance(data["notes"], str), "notes must be a string")
    require(isinstance(data["contractAddresses"], dict), "contractAddresses must be an object")
    require(data["assetIssuers"] == {}, "registry artifacts do not establish asset issuers")
    require(isinstance(data["txHashes"], list), "txHashes must be an array")
    if data["status"] == "not-deployed":
        require(data.keys() == BASE, "unexpected fields in empty deployment record")
        require(not data["verified"] and data["contractAddresses"] == {} and data["txHashes"] == [],
                "not-deployed must contain no deployment or verification claims")
        return
    require(data["status"] == "deployed", "unsupported status")
    require(data.keys() == BASE | DEPLOYED, "invalid deployed manifest fields")
    require(data["networkPassphrase"] == PASSPHRASE, "incorrect testnet passphrase")
    require(data["contractAddresses"].keys() == {"corridor-registry"}, "expected corridor-registry address")
    require(contract_id(data["contractAddresses"]["corridor-registry"]), "invalid contract StrKey or checksum")
    require(len(data["txHashes"]) > 0 and all(hex_hash(x) for x in data["txHashes"]), "invalid transaction hashes")
    require(len(set(data["txHashes"])) == len(data["txHashes"]), "duplicate transaction hashes")
    require(hex_hash(data["sourceCommit"], 40), "invalid source commit")
    for field in ("sourceSha256", "wasmSha256", "abiSha256"):
        require(hex_hash(data[field]), f"invalid {field}")
    require(isinstance(evidence, dict) and wasm is not None and abi is not None, "deployment requires local build evidence")
    require(evidence.get("dirty") is False, "deployment evidence must come from a clean source tree")
    require(evidence.get("sdk") == "27.0.6" and evidence.get("targetProtocol") == 27,
            "unsupported build protocol or SDK")
    for field in DEPLOYED - {"networkPassphrase"}:
        require(data[field] == evidence.get(field), f"mismatched {field}")
    require(hashlib.sha256(wasm).hexdigest() == data["wasmSha256"], "WASM bytes mismatch")
    require(hashlib.sha256(abi).hexdigest() == data["abiSha256"], "ABI bytes mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", default="deployments/testnet/manifest.json")
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.manifest).read_text())
        evidence = wasm = abi = None
        if isinstance(data, dict) and data.get("status") == "deployed":
            evidence = json.loads((args.artifacts / "provenance.json").read_text())
            wasm = (args.artifacts / "stealthbridge_corridor_registry.wasm").read_bytes()
            abi = (args.artifacts / "corridor-registry.abi.json").read_bytes()
        validate(data, evidence, wasm, abi)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Invalid manifest: {error}\n")
    print("Manifest valid locally; no chain existence or transaction verification performed.")


if __name__ == "__main__":
    main()
