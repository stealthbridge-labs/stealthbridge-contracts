import {test} from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {Address, StrKey, xdr} from "@stellar/stellar-sdk";
import {SmartAccountKit} from "smart-account-kit";
import {anchorValid, observationConsistent} from "../src/audit-helpers.mjs";

// Official Protocol 30 Testnet ledger 5810670 (protocolVersion: 30) captured 2026-11-19.
const PROTOCOL_30_HEADER_XDR =
 "AAAAHmw8kthQpKTQ2qpvW8nysSjqV3w3XwdYn1kFTL2VbJJfRshoO26OX/aFza8udj5qHPW9F3S4TWQPH/wbUB9c0ooAAAAAav6zfgAAAAAAAAADAAABofLtJR8AAAAAqCTNGLyddQZNKZpbW6ykO8OqLzJpOBU9jC+btctt8DMAAABALwu6ocrCMwSKXqrNM+5phMsAv7P5VPSOvtmlwHoesw9Zw3kdh7FPCNcKo0vvX0NEporhedkGZcqxMSjy74w9ASta2i/ajySkDZhEYdhSp0Ddo5kv2jQY01lUPNxX6np9jg3A82l7tY+FXEBKbCMemrbgzzt8ik3WDmCmiCN+WrwAWKnuDeC2s6dkAAAAAC1OoDnojwAAAAAAAAAAAA7+BwAAAGQATEtAAAAAyETvn9ZrZehNiqj5Y7KEZHgzZ/RWr6tWLJWAt9U1fKGmmLuxB73eocKyGxtLEOFZzPwpd6hvwktnRHems2/OYSR6CDyv2R7HfBKIznNMdymHVTlBasg62C6eXMNsFhLTcETAaAz0AcKXg+0YuEt37ZCofX9OhI4/zMdPViWaDD1oAAAAAA==";
const PROTOCOL_30_LEDGER = {
 sequence: 5810670,
 id: "c7876b1f049a6dc18528a956427fd0085c4b38d6e8f4241fd85fec4e1ddc1af9",
 closeTime: "1795076990"
};

const VALID_C = "CDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW7JOB";
const VALID_G = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
const VALID_W = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW6AAAAAAAAAAAFKW6A";
const VALID_W_ZERO = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW6AAAAAAAAAAAACCWK";
const VALID_W_MAX = "WDS6HBE6YJSZTRG3VR2HLCNHWJZMKB43BLFFEHEH3Z76WXAF46LW77777777777775SMG";
const VALID_M = "MC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNWAAAAAAAAAAAAGDYO";
const SC_ADDRESS_W_XDR = "AAAABQAAAAAAAAAq5eOEnsJlmcTbrHR1iaeycsUHmwrKUhyH3n/rXAXnl28=";

test("pinned SDK 16.4.1 parses real Protocol 30 Testnet ledger header XDR cleanly", () => {
 const headerXdr = xdr.LedgerHeader.fromXDR(PROTOCOL_30_HEADER_XDR, "base64");
 assert.equal(headerXdr.ledgerVersion(), 30);
 const digest = createHash("sha256").update(headerXdr.toXDR()).digest("hex");
 assert.equal(digest, PROTOCOL_30_LEDGER.id);
 const anchor = { ...PROTOCOL_30_LEDGER, headerXdr };
 assert.equal(anchorValid(anchor, Number(PROTOCOL_30_LEDGER.closeTime) * 1000), true);
 assert.equal(observationConsistent(anchor, anchor, [], Number(PROTOCOL_30_LEDGER.closeTime) * 1000), true);
});

test("pinned SDK 16.4.1 + smart-account-kit 0.10.0 handles Protocol 30 XDR and M-strkeys but rejects W-strkeys", () => {
 assert.equal(StrKey.isValidContract(VALID_C), true);
 assert.equal(StrKey.isValidEd25519PublicKey(VALID_G), true);
 assert.equal(StrKey.isValidMed25519PublicKey(VALID_M), true);
 assert.equal(Address.fromString(VALID_M).toString(), VALID_M);
 assert.equal(typeof StrKey.isValidMuxedContract, "undefined");

 // Low-level XDR ScAddress arm 5 decodes in SDK 16.4.1, but high-level StrKey / Address rejects W addresses.
 const decodedSc = xdr.ScAddress.fromXDR(SC_ADDRESS_W_XDR, "base64");
 assert.equal(decodedSc.switch().name, "scAddressTypeMuxedContract");

 for (const wAddr of [VALID_W, VALID_W_ZERO, VALID_W_MAX]) {
  assert.equal(StrKey.isValidContract(wAddr), false);
  assert.equal(StrKey.isValidEd25519PublicKey(wAddr), false);
  assert.throws(() => Address.fromString(wAddr), /Unsupported address type/);
 }

 // smart-account-kit 0.10.0 preserves XDR base64 string compatibility hook for SDK 17 callers.
 assert.equal(typeof SmartAccountKit.prototype.signAuthEntry, "function");
});
