#!/usr/bin/env python3
"""Validate public method inventory against the real checked-in Soroban sources.

This confirms names/signatures exist in source, NOT that any contract exists
on-chain or that simulating a read succeeds.
"""
import json,re
from pathlib import Path
metadata=json.loads(Path("integrations/public-soroban-interface.v1.json").read_text())
assert metadata["schemaVersion"]==1 and metadata["network"]=="testnet"
assert metadata["status"]=="source-interface-only"
assert set(metadata["contracts"])=={"corridor-registry","policy-registry"}
for name,contract in metadata["contracts"].items():
    source=Path(contract["source"]).read_text()
    methods=set(re.findall(r"pub fn ([a-z_]+)\s*\(",source))
    declared=set(contract["reads"])|set(contract["writes"])
    assert declared<=methods,(name,sorted(declared-methods))
    assert set(contract["reads"]).isdisjoint(set(contract["writes"])),name
    for method,info in contract["reads"].items():
        assert isinstance(info["args"],list) and len(info["args"])<=1,name
        assert info["returns"] in {"Address","Option<Address>","bool","Option<PolicyRecord>"},method
        start=re.search(r"pub fn "+method+r"\s*\(",source)
        assert start is not None,method
        definition=source[start.start():start.start()+320]
        for arg in info["args"]:
            assert arg in definition,(name,method,arg)
print("Soroban public method inventory matches both source contracts; no deployment asserted.")
