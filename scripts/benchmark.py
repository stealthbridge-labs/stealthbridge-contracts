#!/usr/bin/env python3
"""Write native host measurements as JSON and a Markdown baseline table."""
import json
from pathlib import Path
import subprocess
from artifacts import source_snapshot

ROOT = Path(__file__).resolve().parents[1]


def main():
    provenance = json.loads((ROOT / "artifacts/provenance.json").read_text())
    source = source_snapshot()
    if any(provenance[key] != value for key, value in source.items()):
        raise SystemExit("Source differs from build provenance; rerun scripts/artifacts.py")
    output = subprocess.check_output([
        "cargo", "test", "--locked", "-p", "stealthbridge-corridor-registry",
        "resource_profile", "--", "--ignored", "--nocapture", "--test-threads=1",
    ], cwd=ROOT, text=True)
    rows = [json.loads(line.split("RESOURCE ", 1)[1]) for line in output.splitlines() if "RESOURCE " in line]
    if source_snapshot() != source:
        raise SystemExit("Source changed during benchmark; rerun with a stable checkout")
    if len(rows) != 22 or any(row["event_bytes"] for row in rows):
        raise SystemExit("Incomplete benchmark or unexpected contract events")
    result = {"provenance": provenance, "mode": "native-test-host-scoped-mock-auth", "measurements": rows}
    (ROOT / "artifacts/resources.json").write_text(json.dumps(result, indent=2) + "\n")
    table = ["| Operation | ID bytes | CPU instructions | Memory bytes | Read entries (disk/memory) | Write entries | Write bytes | Rent ledger-bytes |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for row in rows:
        table.append(f"| {row['operation']} | {row['id_bytes']} | {row['instructions']} | {row['mem_bytes']} | "
                     f"{row['disk_read_entries']}/{row['memory_read_entries']} | {row['write_entries']} | "
                     f"{row['write_bytes']} | {row['persistent_rent_ledger_bytes']} |")
    header = (
        "# Local native-host resource baseline\n\n"
        f"Source commit: `{provenance['sourceCommit']}`; dirty: `{provenance['dirty']}`.\n\n"
        f"Source SHA-256: `{provenance['sourceSha256']}`.\n\n"
        f"SDK {provenance['sdk']}; protocol {provenance['targetProtocol']}; "
        f"{provenance['rustc']}; CLI {provenance['stellarCli'].splitlines()[0]}.\n\n"
        f"WASM size: {provenance['wasmBytes']} bytes; SHA-256: `{provenance['wasmSha256']}`.\n\n"
        "Native contract execution with scoped mock auth; no VM/signature/transaction fees. "
        "Restoration rows model the local recording host only. See docs/REGISTRY-VERIFICATION.md.\n\n"
    )
    (ROOT / "artifacts/resources.md").write_text(header + "\n".join(table) + "\n")
    print("\n".join(table))


if __name__ == "__main__":
    main()
