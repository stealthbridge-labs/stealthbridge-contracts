#!/usr/bin/env python3
"""Offline structural and boundary validator for deployments/testnet/protocol-deployment.v3.json."""
import json
from pathlib import Path
from validate_manifest import PASSPHRASE, contract_id, hex_hash

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_V3_PATH = ROOT / "deployments" / "testnet" / "protocol-deployment.v3.json"

REQUIRED_GOVERNANCE = {"corridor-registry", "policy-registry", "governance-gate"}
REQUIRED_PROTOCOL = {
    "privacy-verifier",
    "smart-account",
    "settlement-adapter",
    "fee-vault",
}

FALSE_SCOPE_FLAGS = {
    "mainnet_enabled",
    "fiat_payouts_enabled",
    "live_fx_enabled",
    "external_audit_completed",
}

TRUE_SCOPE_FLAGS = {
    "testnet_governance_deployed",
    "testnet_privacy_verifier_deployed",
    "testnet_smart_account_deployed",
    "testnet_settlement_adapter_deployed",
    "testnet_fee_vault_deployed",
    "testnet_groth16_pairing_verified",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_v3(record):
    require(isinstance(record, dict), "v3 manifest must be a JSON object")
    require(record.get("schemaVersion") == 3, "schemaVersion must be 3")
    require(
        record.get("recordType") == "soroban-testnet-protocol-deployment-manifest",
        "unexpected recordType",
    )
    require(record.get("network") == "testnet", "network must be testnet")
    require(
        record.get("networkPassphrase") == PASSPHRASE,
        "unexpected Testnet networkPassphrase",
    )

    scope = record.get("scope")
    require(
        isinstance(scope, dict)
        and set(scope) == (FALSE_SCOPE_FLAGS | TRUE_SCOPE_FLAGS)
        and all(isinstance(v, bool) for v in scope.values()),
        "invalid scope flag keys or types",
    )
    for k in FALSE_SCOPE_FLAGS:
        require(scope[k] is False, f"{k} must remain false on Testnet")
    for k in TRUE_SCOPE_FLAGS:
        require(scope[k] is True, f"{k} must be true in v3 Testnet deployment")

    gov = record.get("governanceContracts")
    require(isinstance(gov, dict), "missing governanceContracts")
    for name in REQUIRED_GOVERNANCE:
        entry = gov.get(name)
        require(isinstance(entry, dict), f"missing governance contract {name}")
        require(contract_id(entry.get("contractId", "")), f"invalid contractId for {name}")
        require(hex_hash(entry.get("wasmSha256", ""), 64), f"invalid wasmSha256 for {name}")
        require(hex_hash(entry.get("deploymentTx", ""), 64), f"invalid deploymentTx for {name}")
        require(
            isinstance(entry.get("deploymentLedger"), int) and entry["deploymentLedger"] > 0,
            f"invalid deploymentLedger for {name}",
        )

    proto = record.get("protocolContracts")
    require(
        isinstance(proto, dict) and set(proto) == REQUIRED_PROTOCOL,
        "protocolContracts must contain exact 4 Testnet protocol contracts",
    )
    seen_ids = set()
    seen_txs = set()
    for name in REQUIRED_PROTOCOL:
        entry = proto[name]
        require(isinstance(entry, dict), f"invalid entry for {name}")
        cid = entry.get("contractId", "")
        require(contract_id(cid) and cid not in seen_ids, f"invalid or duplicate contractId for {name}")
        seen_ids.add(cid)
        require(hex_hash(entry.get("wasmSha256", ""), 64), f"invalid wasmSha256 for {name}")
        require(entry.get("readbackWasmMatches") is True, f"readbackWasmMatches must be true for {name}")
        for tx_field in ("wasmUploadTx", "deploymentTx"):
            tx = entry.get(tx_field, "")
            require(hex_hash(tx, 64) and tx not in seen_txs, f"invalid/duplicate {tx_field} for {name}")
            seen_txs.add(tx)
        require(
            isinstance(entry.get("deploymentLedger"), int) and entry["deploymentLedger"] > 0,
            f"invalid deploymentLedger for {name}",
        )

    pv = proto["privacy-verifier"]
    # The in-house verifier's key is the forgeable SHA-256-labelled smoke-test key (audit C-2).
    require(
        pv.get("registeredKeyClass") == "forgeable-test-setup" and pv.get("realPrivacyProof") is False
        and "OP-1" in str(pv.get("quarantine", "")),
        "privacy-verifier must stay labelled as a forgeable pairing smoke test until OP-1 revokes its key",
    )
    require(hex_hash(pv.get("liveProofVerifyTx", ""), 64), "missing liveProofVerifyTx")
    require(
        isinstance(pv.get("liveProofVerifyLedger"), int) and pv["liveProofVerifyLedger"] > pv["initializeLedger"],
        "liveProofVerifyLedger must follow initializeLedger",
    )
    sa = proto["smart-account"]
    require(sa.get("observedThreshold") == 1 and sa.get("observedPaused") is False, "invalid smart-account state")
    adapter = proto["settlement-adapter"]
    require(
        adapter.get("observedGovernanceGate") == gov["governance-gate"]["contractId"],
        "settlement-adapter must bind to deployed governance-gate",
    )
    vault = proto["fee-vault"]
    require(
        vault.get("observedPaused") is True and vault.get("observedClaimsPaused") is True,
        "fee-vault must remain paused by default on Testnet",
    )
    return len(proto)


def main():
    record = json.loads(DEFAULT_V3_PATH.read_text(encoding="utf-8"))
    count = validate_v3(record)
    print(f"VALID protocol-deployment.v3.json: {count} Testnet protocol contracts verified.")


if __name__ == "__main__":
    main()
