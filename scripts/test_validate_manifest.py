"""All IDs/hashes below are synthetic isolated fixtures, never deployment records."""
import base64
import binascii
from copy import deepcopy
import hashlib
import unittest

from validate_manifest import PASSPHRASE, validate


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.empty = dict(schemaVersion=1, network="testnet", status="not-deployed", verified=False,
                          contractAddresses={}, assetIssuers={}, txHashes=[], notes="test fixture")
        raw = bytes([16]) + bytes(range(32))
        address = base64.b32encode(raw + binascii.crc_hqx(raw, 0).to_bytes(2, "little")).decode()
        self.wasm, self.abi = b"fixture wasm", b"fixture ABI"
        self.evidence = dict(dirty=False, sdk="27.0.6", targetProtocol=27, sourceCommit="a" * 40,
                             sourceSha256="b" * 64, wasmSha256=hashlib.sha256(self.wasm).hexdigest(),
                             abiSha256=hashlib.sha256(self.abi).hexdigest())
        self.deployed = dict(self.empty, status="deployed", networkPassphrase=PASSPHRASE,
                             contractAddresses={"corridor-registry": address}, txHashes=["c" * 64])
        self.deployed.update({k: v for k, v in self.evidence.items() if k.endswith("Sha256") or k == "sourceCommit"})

    def check(self, record):
        validate(record, self.evidence, self.wasm, self.abi)

    def test_valid_empty_and_isolated_deployment_fixture(self):
        validate(self.empty)
        self.check(self.deployed)

    def test_empty_cannot_claim_deployment(self):
        for field, value in [("verified", True), ("contractAddresses", {"corridor-registry": "fake"}),
                             ("txHashes", ["c" * 64]), ("schemaVersion", True), ("extra", 1)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(dict(self.empty, **{field: value}))

    def test_schema_address_network_and_hash_rejections(self):
        cases = [("network", "mainnet"), ("networkPassphrase", "wrong"), ("status", "unknown"),
                 ("contractAddresses", {"corridor-registry": "C" * 56}),
                 ("contractAddresses", {"corridor-registry": "G" * 56}),
                 ("contractAddresses", {}), ("txHashes", ["fake"]), ("txHashes", []),
                 ("verified", "false"), ("sourceCommit", "d" * 40), ("sourceSha256", "d" * 64),
                 ("abiSha256", "d" * 64), ("wasmSha256", "d" * 64), ("unexpected", None)]
        for field, value in cases:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(dict(self.deployed, **{field: value}))
        for field in self.deployed:
            record = deepcopy(self.deployed)
            del record[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.check(record)

    def test_evidence_required_clean_and_byte_matching(self):
        with self.assertRaises(ValueError):
            validate(self.deployed)
        for evidence, wasm, abi in [(dict(self.evidence, dirty=True), self.wasm, self.abi),
                                    (self.evidence, b"tampered", self.abi),
                                    (self.evidence, self.wasm, b"tampered")]:
            with self.assertRaises(ValueError):
                validate(self.deployed, evidence, wasm, abi)



# Keep source ABI conformance in the existing offline Python test suite.
from verify_public_interface import signatures as interface_signatures, validate as validate_interface

_INTERFACE_SOURCES = {
    "corridor-registry": "pub fn __constructor(env: Env) {}\npub fn get_admin(env: Env) -> Result<Address, RegistryError> {}",
    "policy-registry": "pub fn __constructor(env: Env) {}\npub fn admin(env: Env) -> Result<Address, PolicyError> {}",
}
_INTERFACE_METADATA = {
    "schemaVersion": 1, "network": "testnet", "status": "source-interface-only",
    "contracts": {
        "corridor-registry": {"reads": {"get_admin": {"args": [], "returns": "Address"}}, "writes": []},
        "policy-registry": {"reads": {"admin": {"args": [], "returns": "Address"}}, "writes": []},
    },
}


class PublicInterfaceDriftTests(unittest.TestCase):
    def test_declared_source_inventory(self):
        self.assertTrue(validate_interface(_INTERFACE_METADATA, _INTERFACE_SOURCES))

    def test_new_public_method_rejected(self):
        altered = dict(_INTERFACE_SOURCES)
        altered["corridor-registry"] += "\npub fn added(env: Env) -> bool {}"
        with self.assertRaisesRegex(ValueError, "public method drift"):
            validate_interface(_INTERFACE_METADATA, altered)

    def test_read_return_type_drift_rejected(self):
        altered = dict(_INTERFACE_SOURCES)
        altered["policy-registry"] = altered["policy-registry"].replace("Result<Address, PolicyError>", "bool")
        with self.assertRaisesRegex(ValueError, "read signature drift"):
            validate_interface(_INTERFACE_METADATA, altered)

    def test_read_argument_type_drift_rejected(self):
        altered = dict(_INTERFACE_SOURCES)
        altered["corridor-registry"] = altered["corridor-registry"].replace(
            "get_admin(env: Env)", "get_admin(env: Env, id: String)")
        with self.assertRaisesRegex(ValueError, "read signature drift"):
            validate_interface(_INTERFACE_METADATA, altered)

    def test_duplicate_public_method_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate public method"):
            interface_signatures(_INTERFACE_SOURCES["corridor-registry"] +
                                 "\npub fn get_admin(env: Env) -> Address {}")


if __name__ == "__main__":
    unittest.main()
