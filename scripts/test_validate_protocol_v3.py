import copy
import json
import unittest
from pathlib import Path
from validate_protocol_v3 import DEFAULT_V3_PATH, validate_v3


class ValidateProtocolV3Test(unittest.TestCase):
    def test_v3_manifest_validates_cleanly(self):
        record = json.loads(DEFAULT_V3_PATH.read_text(encoding="utf-8"))
        self.assertEqual(validate_v3(record), 4)

    def test_rejects_mainnet_or_fiat_overclaim(self):
        base = json.loads(DEFAULT_V3_PATH.read_text(encoding="utf-8"))
        for bad_flag in ("mainnet_enabled", "fiat_payouts_enabled", "live_fx_enabled", "external_audit_completed"):
            mutated = copy.deepcopy(base)
            mutated["scope"][bad_flag] = True
            with self.assertRaises(ValueError):
                validate_v3(mutated)

    def test_rejects_unpaused_fee_vault_or_governance_mismatch(self):
        base = json.loads(DEFAULT_V3_PATH.read_text(encoding="utf-8"))
        mutated = copy.deepcopy(base)
        mutated["protocolContracts"]["fee-vault"]["observedPaused"] = False
        with self.assertRaises(ValueError):
            validate_v3(mutated)

        mutated2 = copy.deepcopy(base)
        mutated2["protocolContracts"]["settlement-adapter"]["observedGovernanceGate"] = (
            "CBJWFVGD3D2QEFTICRT2GMQRANVR32735OSZ5F77MLBCURDROYGEL362"
        )
        with self.assertRaises(ValueError):
            validate_v3(mutated2)


if __name__ == "__main__":
    unittest.main()
