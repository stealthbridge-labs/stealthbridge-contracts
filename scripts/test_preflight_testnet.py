"""Offline deployment preflight regression tests; no Testnet calls or signer."""
import json
import time
import unittest
from pathlib import Path

import test_verify_artifacts as fixtures
from preflight_testnet import (
    preflight, probe_rpc, valid_operator_address, require_rpc_url, PASSPHRASE
)

VALID = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX"
RPC = "https://soroban-testnet.stellar.org"


class Response:
    def __init__(self, data):
        self.data = json.dumps(data).encode()
        self.headers = {"Content-Length": str(len(self.data))}
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, maximum):
        return self.data[:maximum]


class Opener:
    def __init__(self, network=PASSPHRASE, close_time=None, protocol=27, tamper=False):
        self.network = network
        self.close_time = close_time or int(time.time()) - 5
        self.protocol = protocol
        self.tamper = tamper
        self.calls = []
    def open(self, request, timeout):
        method = json.loads(request.data)["method"]
        self.calls.append(method)
        assert request.get_method() == "POST" and timeout == 8
        if method == "getNetwork":
            value = {"passphrase": self.network}
        else:
            value = {"sequence": 100, "protocolVersion": self.protocol,
                     "closeTime": str(self.close_time), "id": "a" * 64}
        return Response({"jsonrpc": "2.0",
                         "id": "other-id" if self.tamper else "stealthbridge-preflight",
                         "result": value})


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.VerifyArtifactsTests(methodName="test_all_three_contracts_verified")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manifest = self.fixture.root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "schemaVersion": 1, "network": "testnet", "status": "not-deployed",
            "verified": False, "contractAddresses": {}, "assetIssuers": {},
            "txHashes": [], "notes": "No deployment claimed"
        }))

    def test_operator_account_checksum(self):
        self.assertTrue(valid_operator_address(VALID))
        self.assertFalse(valid_operator_address("C" + VALID[1:]))
        self.assertFalse(valid_operator_address(VALID[:-1] + "A"))
        self.assertFalse(valid_operator_address("G" + "A" * 55))

    def test_complete_offline_preflight(self):
        result = preflight(self.fixture.root, self.manifest, operator=VALID)
        self.assertEqual(result["artifacts_verified"], 3)
        self.assertEqual(result["manifest"], "not-deployed")
        self.assertEqual(result["payment_execution"], "disabled")
        self.assertNotIn("testnet_rpc", result)

    def test_rpc_network_protocol_and_freshness_verified(self):
        now = 1790000000
        mock = Opener(close_time=now - 9)
        result = preflight(self.fixture.root, self.manifest, rpc_url=RPC,
                           now=now, opener=mock)
        self.assertEqual(result["testnet_rpc"]["ledger_age_seconds"], 9)
        self.assertEqual(mock.calls, ["getNetwork", "getLatestLedger"])

    def test_wrong_network_stale_ledger_and_protocol_fail_closed(self):
        now = 1790000000
        for opener in [
            Opener(network="Public Global Stellar Network ; September 2015", close_time=now),
            Opener(close_time=now - 190),
            Opener(close_time=now + 31),
            Opener(close_time=now, protocol=26),
            Opener(close_time=now, tamper=True),
        ]:
            with self.subTest(opener=vars(opener)), self.assertRaises(ValueError):
                probe_rpc(RPC, now=now, opener=opener)

    def test_rpc_does_not_allow_insecure_or_query_endpoints(self):
        for url in ["http://example.com", "https://host.invalid?token=abc",
                    "https://user:pw@host.invalid/rpc", "file:///etc/passwd",
                    "https://host.invalid/rpc#fragment"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                require_rpc_url(url)

    def test_unverified_deployment_or_incomplete_artifacts_never_pass(self):
        doc = json.loads(self.manifest.read_text())
        doc["verified"] = True
        self.manifest.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            preflight(self.fixture.root, self.manifest)
        doc["verified"] = False
        self.manifest.write_text(json.dumps(doc))
        (self.fixture.root / "stealthbridge_policy_registry.wasm").unlink()
        with self.assertRaises(OSError):
            preflight(self.fixture.root, self.manifest)


if __name__ == "__main__":
    unittest.main()
