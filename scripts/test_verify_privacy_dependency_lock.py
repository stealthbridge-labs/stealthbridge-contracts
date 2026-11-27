import copy
import hashlib
import json
import unittest
from pathlib import Path

import verify_privacy_dependency_lock as v

LOCK = json.loads((Path(__file__).resolve().parents[1] / "integrations/privacy-dependency-lock.v2.json").read_text())


class PrivacyLockTest(unittest.TestCase):
    def test_canonical_lock_validates_and_both_rails_are_no_go(self):
        lock = v.validate(copy.deepcopy(LOCK))
        self.assertEqual({r: lock["rails"][r]["verdict"] for r in v.RAILS},
                         {"personal-shielded-pool": "NO_GO", "business-confidential-token": "NO_GO"})

    def test_go_is_refused_with_local_setup_blockers_or_unaudited_code(self):
        for mutate in (
            lambda l: l["rails"]["personal-shielded-pool"].update(verdict="GO"),
            lambda l: (l["rails"]["personal-shielded-pool"].update(verdict="GO", blockers=[])),
            lambda l: (l["rails"]["business-confidential-token"].update(verdict="GO")),
        ):
            lock = copy.deepcopy(LOCK)
            mutate(lock)
            with self.assertRaises(ValueError):
                v.validate(lock)

    def test_mainnet_or_extra_rail_is_refused(self):
        lock = copy.deepcopy(LOCK)
        lock["networkPassphrase"] = "Public Global Stellar Network ; September 2015"
        with self.assertRaises(ValueError):
            v.validate(lock)
        lock = copy.deepcopy(LOCK)
        lock["rails"]["generic-private-transfer"] = {}
        with self.assertRaises(ValueError):
            v.validate(lock)

    def test_bad_contract_checksum_and_hash_are_refused(self):
        lock = copy.deepcopy(LOCK)
        c = lock["rails"]["personal-shielded-pool"]["testnetDeployment"]["contracts"][0]
        c["id"] = c["id"][:-1] + ("A" if c["id"][-1] != "A" else "B")
        with self.assertRaises(ValueError):
            v.validate(lock)
        lock = copy.deepcopy(LOCK)
        lock["rails"]["personal-shielded-pool"]["testnetDeployment"]["contracts"][0]["wasmSha256"] = "00"
        with self.assertRaises(ValueError):
            v.validate(lock)

    def test_claiming_an_official_confidential_client_requires_an_explicit_pin(self):
        lock = copy.deepcopy(LOCK)
        lock["rails"]["business-confidential-token"]["clientSdk"]["official"] = "stellar-confidential-token-sdk"
        with self.assertRaises(ValueError):
            v.validate(lock)

    def test_live_check_detects_a_substituted_wasm(self):
        lock = v.validate(copy.deepcopy(LOCK))
        sizes = {c["id"]: c for r in v.RAILS for c in lock["rails"][r]["testnetDeployment"]["contracts"]}

        class Fake(bytes):
            pass

        def honest(cid):
            # Content whose hash we can't forge: emulate by patching the expected digest.
            data = b"\0" * sizes[cid]["wasmBytes"]
            sizes[cid]["wasmSha256"] = hashlib.sha256(data).hexdigest()
            return data

        self.assertEqual(len(v.check_live(lock, honest)), len(sizes))
        lock2 = v.validate(copy.deepcopy(LOCK))
        with self.assertRaises(ValueError):
            v.check_live(lock2, lambda cid: b"\1" * 10)

    def test_source_check_detects_upstream_drift(self):
        lock = copy.deepcopy(LOCK)
        expected = {(r, p): s for r in v.RAILS for p, s in lock["rails"][r]["upstream"]["sourceBlobs"].items()}
        self.assertEqual(v.check_sources(lock, lambda repo, commit, path: next(s for (r, p), s in expected.items() if p == path)), len(expected))
        with self.assertRaises(ValueError):
            v.check_sources(lock, lambda repo, commit, path: "0" * 40)


if __name__ == "__main__":
    unittest.main()
