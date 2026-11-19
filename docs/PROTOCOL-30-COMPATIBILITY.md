# Protocol 30 & Smart-Account Kit Compatibility

- **Live network status checked 2026-11-19**:
  - Stellar Testnet RPC (`getNetwork` / `getLatestLedger`): `protocolVersion = 30`.
  - Stellar Mainnet Horizon (`https://horizon.stellar.org/`): `current_protocol_version = 29`, `supported_protocol_version = 30`.
- **Governance contracts (`contracts/*`)**: Pinned on `soroban-sdk = "=27.0.6"` (`soroban-sdk` 30 is currently `30.0.0-rc.1`). Existing Protocol 27 WASM contracts continue running unchanged on Protocol 30.
- **Smart-Account Preflight (`tools/smart-account-preflight`)**: Pinned on `smart-account-kit: "0.10.0"` + `@stellar/stellar-sdk: "16.4.1"`:
  - SDK `16.4.1` decodes Protocol 30 `LedgerHeader` (`ledgerVersion: 30`) and low-level `ScAddress::MuxedContract` XDR cleanly, so live preflight/audit ledger checks continue operating.
  - SDK `16.4.1` does **not** expose `StrKey.isValidMuxedContract` or accept CAP-84 `W...` strings in `Address.fromString()`.
  - `smart-account-kit@0.10.0` exposes an XDR base64 `AuthEntryInput` string route on `signAuthEntry` for SDK 17 callers, but signing paths do not natively support CAP-84 `W...` addresses and `SECURITY.md` marks the SDK/demo/relayer/indexer unaudited (plus low-severity `elliptic@6.6.1` in optional wallet adapters).
  - See `CUSTOMER-SMART-ACCOUNT-RELEASE-PLAN.md` for all deployment, WebAuthn origin binding, recovery, policy, relayer, and audit gates still required before enabling customer smart accounts.
