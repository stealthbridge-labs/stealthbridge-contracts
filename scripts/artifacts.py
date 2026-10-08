#!/usr/bin/env python3
"""Build twice in isolated directories and record offline artifact provenance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts"
CLI_VERSION = "27.1.0"


def run(*args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, **kwargs).decode().strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_snapshot():
    files = sorted(set(run("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")) - {""})
    source = hashlib.sha256()
    for path in files:
        source.update(path.encode() + b"\0" + (ROOT / path).read_bytes() + b"\0")
    return {
        "sourceCommit": run("git", "rev-parse", "HEAD"),
        "sourceSha256": source.hexdigest(),
        "dirty": bool(run("git", "status", "--porcelain")),
    }


def main():
    cli = os.environ.get("STELLAR", "stellar")
    cli_version = run(cli, "--version")
    if not cli_version.startswith(f"stellar {CLI_VERSION} "):
        raise SystemExit(f"Expected Stellar CLI {CLI_VERSION}: {cli_version}")
    rust = run("rustc", "--version")
    if not rust.startswith("rustc 1.91.0 "):
        raise SystemExit(f"Unexpected compiler: {rust}")
    OUT.mkdir(exist_ok=True)
    source = source_snapshot()
    name = "stealthbridge_corridor_registry.wasm"
    builds = []
    for _ in range(2):
        with tempfile.TemporaryDirectory(prefix="registry-build-") as directory:
            env = os.environ.copy()
            env.update(CARGO_TARGET_DIR=directory, CARGO_INCREMENTAL="0",
                       RUSTFLAGS=f"--remap-path-prefix={ROOT}=/source --remap-path-prefix={directory}=/target")
            subprocess.run(["cargo", "build", "--locked", "--release", "--target", "wasm32v1-none",
                            "-p", "stealthbridge-corridor-registry"], cwd=ROOT, env=env, check=True)
            builds.append((Path(directory) / "wasm32v1-none/release" / name).read_bytes())
    if builds[0] != builds[1]:
        raise SystemExit("Isolated WASM builds differ")
    wasm = OUT / name
    wasm.write_bytes(builds[0])
    # CLI decodes the actual WASM spec section, not a hand-maintained interface.
    abi = run(cli, "contract", "info", "interface", "--wasm", str(wasm), "--output", "json") + "\n"
    (OUT / "corridor-registry.abi.json").write_text(abi)
    if source_snapshot() != source:
        raise SystemExit("Source changed during artifact generation; rebuild a stable checkout")
    metadata = {
        "schemaVersion": 1, "artifactVersion": "corridor-registry/0.1.0",
        **source,
        "wasmSha256": sha(builds[0]), "abiSha256": sha(abi.encode()),
        "wasmBytes": len(builds[0]), "rustc": rust, "stellarCli": cli_version,
        "sdk": "27.0.6", "sdkMajor": 27, "targetProtocol": 27,
        "target": "wasm32v1-none", "reproducibleBuilds": 2,
        "cargoLockSha256": sha((ROOT / "Cargo.lock").read_bytes()),
    }
    (OUT / "provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (OUT / "SHA256SUMS").write_text("".join(
        f"{sha(path.read_bytes())}  {path.name}\n"
        for path in [wasm, OUT / "corridor-registry.abi.json", OUT / "provenance.json"]
    ))
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
