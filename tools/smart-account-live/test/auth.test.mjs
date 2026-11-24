import test from "node:test";
import assert from "node:assert/strict";
import { Keypair, xdr } from "@stellar/stellar-sdk";
import { ed25519AuthSignatureScVal, ed25519SignerId } from "../src/auth.mjs";

test("signer id matches the contract derivation sha256(0x01 || key)", () => {
  const kp = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1));
  const id = ed25519SignerId(kp.rawPublicKey());
  assert.equal(id.length, 32);
  assert.notDeepEqual(id, ed25519SignerId(Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2)).rawPublicKey()));
});

test("signature ScVal is Vec<AuthSignature::Ed25519(id, sig)>", () => {
  const v = ed25519AuthSignatureScVal(Buffer.alloc(32, 3), Buffer.alloc(64, 4));
  const outer = v.vec();
  assert.equal(outer.length, 1);
  const inner = outer[0].vec();
  assert.equal(inner[0].sym().toString(), "Ed25519");
  assert.equal(inner[1].bytes().length, 32);
  assert.equal(inner[2].bytes().length, 64);
  assert.ok(xdr.ScVal.fromXDR(v.toXDR()));
  assert.throws(() => ed25519AuthSignatureScVal(Buffer.alloc(31), Buffer.alloc(64)));
});
