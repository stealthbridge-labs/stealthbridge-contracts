# No fabricated production data policy

Runtime product data is never hardcoded or seeded for the appearance of a functioning payment network. Our application must make a truthful distinction between:
- **Live observed**: Stellar RPC ledger metadata and contract/account events, with source and network shown.
- **Configured**: operator-provisioned corridor records whose asset identity and policies still require on-chain/issuer validation.
- **Unsupported**: private transfers, payouts, issuer controls and FX quotes until independently tested and enabled.
- **Unavailable**: RPC/database/provider failure, shown as an error (not substituted with samples).
- **Test fixture**: synthetic values may be used solely inside isolated unit tests and not compiled into the user-facing product.

No locally invented partners, countries, transaction hashes, balances, completion events, exchange rates, fiat providers, or privacy proofs should be shown to end-users. Read-only API state without a production cryptographic rail is not a completed settlement product.
