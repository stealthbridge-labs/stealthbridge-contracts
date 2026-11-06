#!/usr/bin/env python3
"""Offline source-only release guard. Explicit checks must survive python -O."""
import json
from pathlib import Path

def require(allowed, reason):
    if not allowed:
        raise ValueError(reason)

def verify(manifest, interface):
    require(type(manifest) is dict and type(interface) is dict,
            "release record must be a JSON object")
    require(type(manifest.get("schemaVersion")) is int and
            manifest["schemaVersion"] == 1 and
            manifest.get("network") == "testnet" and
            manifest.get("status") == "not-deployed" and
            manifest.get("verified") is False,
            "unverified source manifest cannot claim deployment")
    require(type(manifest.get("contractAddresses")) is dict and
            not manifest["contractAddresses"] and
            type(manifest.get("assetIssuers")) is dict and
            not manifest["assetIssuers"] and
            type(manifest.get("txHashes")) is list and
            not manifest["txHashes"],
            "unsupported deployment, asset or transaction evidence")
    require(type(interface.get("schemaVersion")) is int and
            interface["schemaVersion"] == 1 and
            interface.get("network") == "testnet" and
            interface.get("status") == "source-interface-only" and
            type(interface.get("contracts")) is dict,
            "source interface is not approved for financial execution")
    return True

if __name__ == "__main__":
    manifest = json.loads(Path("deployments/testnet/manifest.json").read_text())
    interface = json.loads(Path("integrations/public-soroban-interface.v1.json").read_text())
    verify(manifest, interface)
    print("PASS: undeployed source-only release boundary")
