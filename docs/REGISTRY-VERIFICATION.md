# Corridor registry verification and resource baseline

## Reproduce

Run the commands in the root README. Python 3.9+ uses only its standard library.
`STELLAR=/absolute/path/to/stellar python3 scripts/artifacts.py` supports a CLI
outside PATH. All scripts operate locally; none deploys, funds an account, signs,
or calls an RPC. CI uses read-only repository permissions and publishes
`corridor-registry-<commit>` artifacts.

Pinned versions: Rust 1.91.0, SDK 27.0.6, host 27.0.1, CLI 27.1.0, protocol 27,
target `wasm32v1-none`. Cargo.lock fixes transitive versions and checksums.
The CLI's complete version output, compiler version, source commit, source-tree
digest and dirty flag appear in `artifacts/provenance.json`. The source digest is
SHA-256 over sorted tracked/unignored file names, NUL, file bytes, NUL. Run from a
clean checkout for releasable evidence. Ignored build products are excluded.
Artifact generation rejects source changes during its run. The benchmark rejects
stale build provenance or source changes during measurement.

`scripts/artifacts.py` builds the corridor WASM twice with separate temporary
target directories, remapped source/target paths, no incremental compilation,
and the workspace release profile. It rejects different bytes. This proves local
repeatability under the recorded toolchain, not universal reproducibility across
arbitrary operating systems or future compilers. `SHA256SUMS` covers the WASM,
the ABI decoded from its spec section by the CLI, and provenance. The workspace
CI also compiles the policy contract; its behavior is outside these three issues.

## Authorization and lifetime tests

The corridor suite checks exact `(contract, function, arguments, signer)` mock
authorizations for enable/disable, pause/unpause and both handover steps. Missing,
wrong, argument-mismatched and retired-admin approvals fail. Failed writes leave
the relevant state unchanged; a pending nominee cannot be accepted by the old
admin. Acceptance without a nominee returns `NoPendingAdmin`.

These are authorization-tree tests, not cryptographic signature tests. In SDK
27.0.6, `Env::register` automatically authorizes constructors. Deployment and
constructor signature verification therefore remain outside this suite.

Fixtures explicitly set ledger sequence 100, minimum persistent lifetime 100,
and maximum lifetime 519400 ledgers. They verify both instance and corridor TTL:

- A write extends to 518400 remaining ledgers.
- At threshold + 1 (17281) a write does not renew; at threshold (17280) it does.
- Reads do not renew live data. TTL 0 is still live for the current ledger; a
  write at that boundary renews it.
- Pausing renews the instance but not each corridor key.
- After expiry, the pinned recording host restores the value and admin to its
  configured minimum lifetime (99 remaining ledgers). A later authorized write
  extends both again. This exercises the host's restoration model, not a network
  restoration transaction or its actual rent charge.

### Restoration runbook

Monitor the code/instance TTL and each persistent corridor key separately.
Before submitting a later authorized invocation, simulate it against the intended
network and retain the simulation's resource/restore list. Review the restored
keys and rent budget. If restoration needs a separate `RestoreFootprintOp`, have
the authorized operator prepare that operation, wait for success, then simulate
the original invocation again. Never recreate an archived key as if it were
missing, and never interpret an RPC/storage failure as proof of a disabled flag.
No automated keepalive or restoration transaction is introduced here.

Protocol 23+ supports restoration through the invocation restore list; omitting
needed entries can fail before contract execution. Network behavior and cost must
be independently exercised before any deployment claim. See the official
[state archival guide](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival)
and the pinned
[host restoration implementation](https://github.com/stellar/rs-soroban-env/blob/v27.0.1/soroban-env-host/src/storage.rs).

## Quantitative measurements

`python3 scripts/benchmark.py` runs the ignored `resource_profile` test and writes
`artifacts/resources.json` plus a human-readable baseline table in
`artifacts/resources.md`. Both carry exact source and tool versions and WASM size.
CI uploads them together with the build evidence. Test-only IDs contain repeated
`x` bytes, with lengths 8 and 128; they identify no payment corridor.

For each size the table records first/repeated/changed writes, reads, pause,
unpause, proposal, acceptance, rejected unauthenticated writes, threshold renewal,
and access after modeled archival. Measurements are captured immediately after
each top-level call, before TTL/state inspection can change the last-call meter.
Rows report modeled CPU instructions, memory bytes, disk and memory entry reads,
write entries/bytes, event bytes, and persistent rent ledger-bytes/entry bumps.
Write bytes and entry counts describe the invocation footprint, not a full
database-size estimate. The JSON preserves all these counters, including zeroes.

Admin-call rows include the host's authorization path with scoped mock approval;
the footprint and rent counters can also include synthetic authorization state.
the rejected row shows the no-approval failure path. These are different execution
paths, so their difference is not an isolated signature-verification cost. Real
signature verification, VM startup/execution, WASM reads/rent, transaction envelope
size, and RPC/network configuration are not measured by native tests. Binary size
is measured separately from the actual release WASM. No result is a network fee
quote, gas price, latency estimate, or mainnet capacity claim. The pinned
[SDK cost-estimation documentation](https://docs.rs/soroban-sdk/27.0.6/soroban_sdk/testutils/cost_estimate/struct.CostEstimate.html)
describes these limits.

Proposed regression policy: compare only identical SDK/host/compiler/profile and
fixture versions against an accepted clean-commit artifact. Request review for
>10% CPU/memory/WASM growth; review any additional footprint entry, event, or
unexpected rent bump. Absolute CPU/memory differences below 1000 units may be
treated as noise only with an explanation. Require a reviewed new baseline after
toolchain changes. This is a review policy, not a production cost guarantee or an
automated CI threshold yet.

## Event and disclosure decision

The contract emits no application events; tests and benchmark output enforce this.
Publishing corridor identifiers in topics would add an avoidable index of policy
changes and possible private-payment correlations. State, admin addresses,
arguments, and invocation timing are still public. Opaque identifiers are not
confidentiality: operators must never encode participant identities, amounts, or
links to private payments in corridor IDs. This registry does not move assets.

## Artifact versions and rollback

Archive the full artifact set under the source commit and contract package version
(`corridor-registry/0.1.0` initially). ABI changes require explicit compatibility
review and an appropriate package version bump. Keep old checksums, ABI, source and
deployment records available. A bad candidate can be discarded before deployment.
Neither contract currently exposes a WASM-upgrade method; an on-chain rollback is
not implied by retaining an old binary. A later replacement/migration requires
separate governance authorization, integration coordination, and evidence.
