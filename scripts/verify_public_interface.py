#!/usr/bin/env python3
"""Validate source-level Soroban discovery, never on-chain deployment evidence."""
import json
import re
from pathlib import Path

SIGNATURE = re.compile(r"pub\s+fn\s+([a-z_]+)\s*\(([^)]*)\)\s*(?:->\s*([^\{]+?))?\s*\{", re.S)
ALLOWED_RETURNS = {"Address", "Option<Address>", "bool", "Option<PolicyRecord>"}


def signatures(source):
    """Extract public contract methods from the small, pinned Rust interface subset."""
    methods = {}
    for name, args, result in SIGNATURE.findall(source):
        if name in methods:
            raise ValueError(f"duplicate public method: {name}")
        params = [part.strip() for part in args.split(",") if part.strip()]
        if not params or params[0] != "env: Env":
            raise ValueError(f"{name}: expected Env as first argument")
        arg_types = []
        for param in params[1:]:
            if ":" not in param:
                raise ValueError(f"{name}: unrecognized argument")
            arg_types.append(param.split(":", 1)[1].strip())
        result = (result or "()").strip()
        if result.startswith("Result<") and result.endswith(">"):
            result = result[len("Result<"):-1].split(",", 1)[0].strip()
        methods[name] = (arg_types, result)
    return methods


def validate(metadata, sources):
    if type(metadata.get("schemaVersion")) is not int or metadata["schemaVersion"] != 1:
        raise ValueError("unsupported interface version")
    if metadata.get("network") != "testnet" or metadata.get("status") != "source-interface-only":
        raise ValueError("only undeployed Testnet source interfaces are permitted")
    if set(metadata.get("contracts", {})) != {"corridor-registry", "policy-registry"}:
        raise ValueError("unexpected contract inventory")
    for name, contract in metadata["contracts"].items():
        methods = signatures(sources[name])
        reads = contract["reads"]
        writes = contract["writes"]
        if not isinstance(reads, dict) or not isinstance(writes, list) or len(writes) != len(set(writes)):
            raise ValueError(f"{name}: invalid read/write inventory")
        declared = set(reads) | set(writes)
        if set(reads) & set(writes):
            raise ValueError(f"{name}: read/write overlap")
        # __constructor is a lifecycle hook, not a callable registry discovery method.
        actual = set(methods) - {"__constructor"}
        if declared != actual:
            raise ValueError(f"{name}: public method drift: missing={sorted(actual - declared)} stale={sorted(declared - actual)}")
        for method, info in reads.items():
            args, result = methods[method]
            if not isinstance(info, dict) or info.get("args") != args or info.get("returns") != result:
                raise ValueError(f"{name}.{method}: read signature drift")
            if len(args) > 1 or result not in ALLOWED_RETURNS:
                raise ValueError(f"{name}.{method}: unsupported public read signature")
    return True


def main():
    metadata = json.loads(Path("integrations/public-soroban-interface.v1.json").read_text())
    sources = {name: Path(contract["source"]).read_text() for name, contract in metadata["contracts"].items()}
    validate(metadata, sources)
    print("Soroban public method inventory and read signatures match source; no deployment asserted.")


if __name__ == "__main__":
    main()
