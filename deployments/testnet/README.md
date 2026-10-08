# deployments/testnet

The manifest is intentionally `not-deployed`. Validate without network access:

```sh
python3 scripts/validate_manifest.py
```

The schema is enforced by `scripts/validate_manifest.py`. Version 1 requires
`schemaVersion` (integer 1), `network` (`testnet`), `status`, boolean `verified`,
`contractAddresses` object, empty `assetIssuers` object, `txHashes` array, and a
string `notes`. Unknown fields are rejected. For `not-deployed`, addresses and
transaction hashes must be empty and `verified` must be false. No network
passphrase, address or source hash is fabricated for an empty record.

A `deployed` record additionally requires:

- `networkPassphrase`: exactly `Test SDF Network ; September 2015`.
- `contractAddresses`: exactly a `corridor-registry` entry with a valid contract
  StrKey (C prefix, base32 length/version and CRC16-XModem checksum).
- Nonempty, distinct `txHashes`: lowercase 64-character hex transaction hashes.
- `sourceCommit`: a 40-character lowercase Git commit hash.
- `sourceSha256`, `wasmSha256`, `abiSha256`: lowercase SHA-256 hashes matching the
  local clean-build `artifacts/provenance.json`. The validator also hashes the
  WASM and ABI bytes and compares them with the record.

Only the corridor artifact is supported by this schema; extend it explicitly
before recording other contracts. Synthetic IDs exist only inside isolated
validator tests and must never be copied into the deployment manifest.

After a separately authorized Testnet deployment, a maintainer should:

1. Preserve the clean source commit and CI artifact set. Verify `SHA256SUMS` and
   independently rebuild that commit with the pinned toolchain.
2. Obtain the actual successful deployment transaction hash from the submitted
   transaction. Query the correct Testnet RPC, inspect the result/ledger and
   network identity, and confirm the created contract ID.
3. Fetch the deployed WASM and compare its SHA-256 and extracted interface with
   the archived artifacts. Independently inspect the initialized admin and
   governance state. Record evidence links and the verification procedure in
   `notes`; do not include signer secrets.
4. Insert these actual IDs, hashes and passphrase into a reviewed manifest
   change. Set `verified` true only after the independent chain checks succeed.
5. Run the validator with `--artifacts PATH` pointing at that exact artifact set.

The validator proves schema and local hash consistency only. A valid-looking
address or transaction hash does not establish chain existence or successful
deployment, and the script never sets `verified` or submits any transaction.
Keep historical evidence with the versioned release when replacing a record.
