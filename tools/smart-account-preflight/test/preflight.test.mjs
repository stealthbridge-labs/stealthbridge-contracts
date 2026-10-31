import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {validateManifest,validateCodeEntry,validateContractEntry} from "../src/preflight.mjs";
import {TESTNET} from "../src/manifest.mjs";
test("pins official Testnet wallet and authorization digest",()=>{
 assert.equal(validateManifest(),true);
 for(const bad of [
  {...TESTNET,networkPassphrase:"Public Global Stellar Network ; September 2015"},
  {...TESTNET,rpcUrl:"https://evil.invalid"},
  {...TESTNET,kitVersion:"0.9.0"},
  {...TESTNET,accountWasmHash:"0".repeat(64)},
  {...TESTNET,authDigestScheme:"legacy-concat"},
  {...TESTNET,contracts:{...TESTNET.contracts,webauthn:{id:"not-C",hash:"00"}}}
 ])assert.throws(()=>validateManifest(bad));
});
test("missing account, policy or unsafe TTL cannot pass",()=>{
 const hash=TESTNET.accountWasmHash;
 assert.throws(()=>validateCodeEntry(undefined,hash,48273,1000));
 assert.throws(()=>validateCodeEntry({liveUntilLedgerSeq:1100},hash,48273,1000));
 assert.throws(()=>validateContractEntry({liveUntilLedgerSeq:1100},TESTNET.contracts.webauthn.hash,1000));
});
test("tool contains no wallet deployment, transaction submission or secret extraction",()=>{
 const src=readFileSync(new URL("../src/preflight.mjs",import.meta.url),"utf8");
 assert.doesNotMatch(src,/\.(?:sendTransaction|createWallet|signTransaction|submitTransaction|keys\.secret)\s*\(/);
 assert.match(src,/broadcastTransactions:0/);
 assert.match(src,/canDeployCustomerWallet:false/);
});
