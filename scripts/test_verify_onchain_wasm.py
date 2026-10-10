"""Read-only Testnet bytecode attestation checks, entirely mocked and offline."""
import base64
import binascii
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_verify_artifacts as fixtures
from verify_artifacts import CONTRACT_FILES
from verify_onchain_wasm import compare_artifacts, fetch_testnet_wasm, validate_contract_ids


def contract_id(index):
    raw = bytes([16]) + bytes([index]) * 32
    return base64.b32encode(raw + binascii.crc_hqx(raw, 0).to_bytes(2, "little")).decode()


class OnChainWasmTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.VerifyArtifactsTests(methodName="test_all_three_contracts_verified")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.ids = {name: contract_id(i+1) for i, name in enumerate(CONTRACT_FILES)}
        self.content = {
            self.ids[name]: (self.fixture.root / paths[0]).read_bytes()
            for name, paths in CONTRACT_FILES.items()
        }

    def test_matching_three_contract_instances_do_not_claim_auth_or_funds(self):
        verified = compare_artifacts(self.fixture.root, self.ids, fetcher=self.content.__getitem__)
        self.assertEqual(set(verified["bytecode_matches"]), set(CONTRACT_FILES))
        self.assertFalse(verified["admin_verified"])
        self.assertFalse(verified["constructor_bindings_verified"])
        self.assertFalse(verified["payment_execution_enabled"])

    def test_wrong_contract_id_and_duplicate_binding_rejected(self):
        for ids in [
            {**self.ids, "governance-gate": "C" * 56},
            {**self.ids, "governance-gate": self.ids["corridor-registry"]},
            {"corridor-registry": self.ids["corridor-registry"]},
        ]:
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                validate_contract_ids(ids)

    def test_wrong_chain_wasm_is_never_accepted(self):
        broken = dict(self.content)
        broken[self.ids["governance-gate"]] += b"modified"
        with self.assertRaisesRegex(ValueError, "On-chain WASM differs"):
            compare_artifacts(self.fixture.root, self.ids, fetcher=broken.__getitem__)

    def test_read_only_stellar_cli_fetch_no_signer(self):
        calls = []
        def fake_run(args, **kwargs):
            calls.append((args,kwargs))
            Path(args[args.index("--out-file")+1]).write_bytes(b"fixture-contract")
        with patch("verify_onchain_wasm.subprocess.run", side_effect=fake_run):
            self.assertEqual(fetch_testnet_wasm(self.ids["corridor-registry"]), b"fixture-contract")
        args, options = calls[0]
        self.assertEqual(args[:3], ["stellar", "contract", "fetch"])
        self.assertEqual(args[args.index("--network")+1], "testnet")
        self.assertNotIn("--source-account", args)
        self.assertNotIn("--sign-with-key", args)
        self.assertTrue(options["check"])


if __name__ == "__main__":
    unittest.main()
