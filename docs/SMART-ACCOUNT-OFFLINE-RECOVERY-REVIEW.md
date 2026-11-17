# Operator-only offline recovery evidence review

This review reconciles the seven pinned public Testnet entries from `audit:testnet` with the JSON produced by `review:archival`. It produces operator investigation tasks. It never creates an account, enables a vault, privacy or payouts, or authorizes any financial execution. No report or input payload can grant those permissions. It builds and broadcasts zero transactions. No signing, deployment, secret access, RPC or Core requests occur during reconciliation.

## Prepare the two files

Save **two complete, unedited schema-version-1 JSON objects** outside this repository, using an operator-controlled directory. Use the stdout JSON from the existing [public audit and Core review](../tools/smart-account-preflight/README.md), without npm banners, shell prompts, stderr, Markdown fences or extra text. Suggested names:

```text
/absolute/operator-evidence/public-audit.json
/absolute/operator-evidence/core-review.json
```

These files contain public observations only; do not include keys or credentials. They must be readable regular files, at most 524,288 bytes each, with no leaf symlinks. The reviewer opens inputs read-only, rejects special files, bounds the actual bytes read, validates UTF-8/JSON, and checks for changes during reading. Keep the directory under operator control during review.

Collection is a **separate networked read-only step**, not performed by this offline command. Save observations collected together: each public ledger bracket must span at most 12 ledgers; Core must be within 12 ledgers of its own public RPC bracket. Every audit entry and both corresponding bracket endpoints must be within 24 ledgers of the paired Core observation/bracket. Do not substitute a previous successful snapshot when Core is unavailable. If the existing historical audit and Core review do not align, retain them as historical records and obtain a newly paired observation through a separately authorized collection process.

The Core query report must retain `source.type: operator_owned_stellar_core_http_query` and `source.coreNetworkVerified: false`. Independently verify the operator-owned node's Testnet network, trusted history/quorum configuration and synchronization. The public RPC's Testnet passphrase and nearby ledger numbers **do not authenticate Core's network**.

## Run offline

With the already installed, pinned package dependencies, run from the repository root:

```bash
cd tools/smart-account-preflight
npm run --silent review:recovery -- \
  --audit-json /absolute/operator-evidence/public-audit.json \
  --core-json /absolute/operator-evidence/core-review.json
```

Both paths are mandatory; either flag order works. No other flags or URLs are accepted. The command prints JSON to stdout, creates no files, and always exits **1**, including when evidence is coherent: operator review remains required. Optional stdout redirection is an operator shell action; choose a third file outside the repository and never redirect onto either input. Do not install dependencies as part of an offline run.

## Interpret the report

| Result/state | Meaning |
| --- | --- |
| `blocked` | Missing/invalid input, invalid pins, inconsistent schema/identity/hash/TTL, unaligned snapshots, indeterminate entries or conflicting findings. Obtain a new paired observation and investigate. |
| `review_required` | Structurally coherent historical claims; human review is still required. This is never a deployment or execution gate. |
| `archive_candidate_pending_independent_core_trust` | Public live entry unavailable and Core reports an identity-checked archived entry. Conditional operator evidence only; independently establish Core trust before considering any separate restoration plan. |
| `investigate_missing` | Public live entry unavailable and Core reports not found. Not proof of archival; no restoration inference. |
| `live_ttl_review` | Both observations report live, matching expiration; either remaining TTL is at most 120,960 ledgers. Review lifecycle maintenance separately. |
| `live_lifecycle_review` | Both observations report live with the same expiration above the threshold. No account, custody or financial authorization follows. |

The reviewer requires the exact producer envelope, network, policy and disabled permission fields. It validates all seven entries in manifest order, contract IDs, expected and observed hashes, computed code SHA claims, account size, Core ledger-key SHA-256 and last-modified ledgers. TTL must equal expiration minus the entry's observation ledger. Zero/expired public TTL never becomes verified live TTL or proves archival. Different live expirations block reconciliation even if an intervening extension could explain them; obtain a coherent paired observation. Summary flags, actions and minima must match recomputation from entries.

The output preserves per-entry public/Core status, observed hashes, identity claims and separate live TTL observations. Its source stays `operator_owned`, `coreNetworkVerified` and `independentCoreTrustEstablished` stay false, and all execution capabilities stay false.

## Authenticity and freshness limits

These JSON schemas contain **claims, not signed proofs, raw entry XDR or saved ledger headers/close times**. Offline review checks consistency with the pinned artifacts; it cannot recompute WASM hashes from absent bytes, authenticate the collector, identify a completely self-consistent fabricated report, or determine current chain freshness. `inputAuthenticityEstablished: false` and `currentFreshnessEstablished: false` explicitly preserve that boundary. Ledger alignment detects a stale *paired snapshot*, not elapsed wall-clock age. An old aligned pair remains historical only; its TTL is never a current usable balance of ledgers.

Keep original files and independently established provenance. Do not repair rejected evidence by editing flags, hashes or ledger numbers. Missing Core evidence always blocks; no cached earlier success is used. Any restoration, extension, account pilot or financial action requires its own independently reviewed evidence and explicit authorization outside this tool.

The JSON in `test/fixtures/` is synthetic schema-faithful adversarial-test material. It is not a retained chain observation or evidence of current availability.
