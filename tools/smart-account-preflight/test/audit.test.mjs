import {test} from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {xdr} from "@stellar/stellar-sdk";
import {validateCodeEntry,validateContractEntry} from "../src/preflight.mjs";
import {TESTNET} from "../src/manifest.mjs";
import {auditLive,auditExitCode,collectEntries,validateAuditPins} from "../src/audit.mjs";
import {validateDependencyPins,targetsFor,observeEntry,anchorValid,observationConsistent,summarize,REVIEW_TTL_LEDGERS} from "../src/audit-helpers.mjs";
const hash=b=>createHash("sha256").update(b).digest("hex");
const seq=5487598,now=1793620800000,targets=targetsFor(TESTNET);
function anchor(sequence=seq,time=now/1000){
 const zero=Buffer.alloc(32);
 const header=new xdr.LedgerHeader({ledgerVersion:25,previousLedgerHash:zero,
  scpValue:new xdr.StellarValue({txSetHash:zero,closeTime:xdr.Uint64.fromString(String(time)),upgrades:[],ext:xdr.StellarValueExt.stellarValueBasic()}),
  txSetResultHash:zero,bucketListHash:zero,ledgerSeq:sequence,totalCoins:xdr.Int64.fromString("0"),feePool:xdr.Int64.fromString("0"),inflationSeq:0,idPool:xdr.Uint64.fromString("0"),baseFee:100,baseReserve:1,maxTxSetSize:1,skipList:[zero,zero,zero,zero],ext:new xdr.LedgerHeaderExt(0)});
 return {id:hash(header.toXDR()),sequence,closeTime:String(time),headerXdr:header};
}
function instance(t,ttl=200000,wasm=t.hash){
 const data=t.key.contractData();
 return {key:t.key,lastModifiedLedgerSeq:seq-1,liveUntilLedgerSeq:seq+ttl,val:xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({ext:new xdr.ExtensionPoint(0),contract:data.contract(),key:data.key(),durability:data.durability(),val:xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({executable:xdr.ContractExecutable.contractExecutableWasm(Buffer.from(wasm,"hex")),storage:[]}))}))};
}
function code(t,bytes=Buffer.from("fixture wasm"),ttl=200000){
 return {key:t.key,liveUntilLedgerSeq:seq+ttl,val:xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({ext:new xdr.ContractCodeEntryExt(0),hash:Buffer.from(t.hash,"hex"),code:bytes}))};
}
function fixtures(){
 const bytes=Buffer.from("fixture wasm");
 return targets.map(t=>t.kind==="instance"?t:{...t,key:xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({hash:Buffer.from(hash(bytes),"hex")})),hash:hash(bytes),size:bytes.length});
}
function fake({entry,network=TESTNET.networkPassphrase,anchors=[anchor(),anchor()]}={}){
 const calls=[];
 const api={async getNetwork(){calls.push("getNetwork");return {passphrase:network};},async getLatestLedger(){calls.push("getLatestLedger");return anchors.shift();},async getLedgerEntries(key){calls.push(key.toXDR("base64"));const t=targets.find(t=>t.key.toXDR("base64")===key.toXDR("base64"));return entry?entry(t):{latestLedger:seq,entries:t.kind==="instance"?[instance(t)]:[]};}};
 return {calls,server:new Proxy(api,{get(obj,key){assert.ok(Object.hasOwn(obj,key),`Unexpected API ${String(key)}`);return obj[key];}})};
}
test("healthy synthetic XDR entries and deterministic summary without any broadcast API",async()=>{
 const ts=fixtures();const server={async getLedgerEntries(key){const t=ts.find(t=>t.key.toXDR("base64")===key.toXDR("base64"));return {latestLedger:seq,entries:[t.kind==="code"?code(t):instance(t)]};}};
 const items=await collectEntries(server,ts);
 assert.equal(items.length,7);assert.ok(items.every(i=>i.status==="healthy"));assert.ok(observationConsistent(anchor(),anchor(),items,now));
 assert.deepEqual(summarize(items,true),{verified:true,minimumTtlRemainingLedgers:200000,minimumTtlScope:"observed_entries_with_valid_ttl_only",actions:[]});
 assert.deepEqual(items,await collectEntries(server,ts));assert.equal(auditExitCode({summary:summarize(items,true)}),0);
});
test("code SHA-256, embedded hash, size and returned key checked independently",()=>{
 const t=fixtures()[0],result=e=>observeEntry(t,{latestLedger:seq,entries:[e]});
 assert.equal(result(code(t)).status,"healthy");assert.equal(result(code(t,Buffer.from("tampered"))).status,"mismatch");
 const embedded=code(t);embedded.val.contractCode().hash(Buffer.alloc(32));assert.equal(result(embedded).status,"mismatch");
 const key=code(t);key.key=targets[0].key;assert.equal(result(key).reason,"returned_key_mismatch");
 assert.equal(observeEntry({...t,size:99},{latestLedger:seq,entries:[code(t)]}).status,"mismatch");
});
test("TTL review boundary and historical measurements are low TTL, never absence",()=>{
 const t=targets[1];
 for(const ttl of [0,720,17432,18036,18038,REVIEW_TTL_LEDGERS]){
  const item=observeEntry(t,{latestLedger:seq,entries:[instance(t,ttl)]});assert.equal(item.status,"low_ttl");assert.equal(item.ttlRemainingLedgers,ttl);assert.deepEqual(summarize([item],true).actions,["review_extension"]);
 }
 assert.equal(observeEntry(t,{latestLedger:seq,entries:[instance(t,REVIEW_TTL_LEDGERS+1)]}).status,"healthy");
 for(const ttl of [undefined,null,"123",-1,NaN,2**32]){
  const e=instance(t);e.liveUntilLedgerSeq=ttl;const item=observeEntry(t,{latestLedger:seq,entries:[e]});assert.equal(item.status,"indeterminate");assert.equal(item.ttlRemainingLedgers,null);
 }
});
test("RPC zero TTL sentinel is unavailable-live, never a healthy code or an invented expiry",()=>{
 const codeTarget=fixtures()[0],policy=targets[1];
 for(const [target,raw] of [[codeTarget,code(codeTarget)],[policy,instance(policy)]]){
  raw.liveUntilLedgerSeq=0;
  const found=observeEntry(target,{latestLedger:seq,entries:[raw]});
  assert.equal(found.status,"unavailable_live_entry");
  assert.equal(found.reason,"rpc_zero_ttl_no_verified_live_entry");
  assert.equal(found.liveUntilLedgerSeq,null);
  assert.equal(found.ttlRemainingLedgers,null);
  assert.deepEqual(summarize([found],true).actions,["investigate_restore_or_republish"]);
 }
 const raw=code(codeTarget);
 raw.liveUntilLedgerSeq=seq-1;
 const outdated=observeEntry(codeTarget,{latestLedger:seq,entries:[raw]});
 assert.equal(outdated.status,"unavailable_live_entry");
 assert.equal(outdated.liveUntilLedgerSeq,seq-1);
 assert.equal(outdated.ttlRemainingLedgers,null);
});

test("missing account code does not prevent any other observation or invent zero TTL",async()=>{
 const f=fake(),r=await auditLive({server:f.server,now:()=>now});
 assert.equal(f.calls.length,10);assert.equal(r.entries.length,7);assert.equal(r.entries[0].status,"unavailable_live_entry");assert.match(r.entries[0].reason,/archive_or_nonexistent_ambiguous/);
 assert.equal(r.entries[0].liveUntilLedgerSeq,null);assert.equal(r.entries[0].ttlRemainingLedgers,null);assert.ok(r.entries.filter(i=>i.kind==="instance").every(i=>i.status==="healthy"));
 assert.equal(r.summary.minimumTtlRemainingLedgers,200000);assert.deepEqual(r.summary.actions,["investigate_restore_or_republish"]);assert.equal(auditExitCode(r),1);
 for(const name of ["canDeployCustomerWallet","customerWalletCreated","credentialRecoveryVerified","verifiedFinancialExecution"])assert.equal(r[name],false);
 assert.equal(r.broadcastTransactions,0);assert.equal(r.transactionsBuilt,0);
});
test("missing instance, partial RPC failure and mismatch remain independent",async()=>{
 const f=fake({entry:t=>{
  if(t.name==="webauthn_instance")return {latestLedger:seq,entries:[]};
  if(t.name==="threshold_instance")throw Error("sensitive injected response");
  if(t.name==="spendingLimit_instance")return {latestLedger:seq,entries:[instance(t,200000,"00".repeat(32))]};
  return {latestLedger:seq,entries:[]};
 }}),r=await auditLive({server:f.server,now:()=>now});
 for(const [name,status] of [["webauthn_instance","unavailable_live_entry"],["threshold_instance","indeterminate"],["spendingLimit_instance","mismatch"]])assert.equal(r.entries.find(i=>i.name===name).status,status);
 assert.equal(f.calls.length,10);assert.doesNotMatch(JSON.stringify(r),/sensitive/);assert.deepEqual(r.summary.actions,["investigate_mismatch","investigate_restore_or_republish","retry_observation"]);
});
test("wrong network fails closed before entry calls",async()=>{
 const f=fake({network:"Public Global Stellar Network ; September 2015"}),r=await auditLive({server:f.server,now:()=>now});assert.deepEqual(f.calls,["getNetwork"]);assert.equal(r.network.verified,false);assert.equal(auditExitCode(r),1);assert.ok(r.entries.every(i=>i.status==="indeterminate"));
});
test("fresh canonical header and uint32 ledgers with bounded consistent spans required",async()=>{
 assert.equal(anchorValid(anchor(),now),true);
 for(const a of [anchor(seq,now/1000-121),anchor(seq,now/1000+31),{...anchor(),id:"00".repeat(32)},{...anchor(),sequence:seq+1}])assert.equal(anchorValid(a,now),false);
 for(const n of [undefined,"5487598",NaN,Infinity,0,-1,1.5,2**32])assert.equal(observeEntry(targets[0],{latestLedger:n,entries:[]}).status,"indeterminate");
 for(const anchors of [[anchor(),anchor(seq+13)],[anchor(),anchor(seq-1)],[anchor(),{...anchor(),sequence:"5487598"}],[anchor(seq,now/1000-121),anchor()]]){
  const f=fake({anchors}),r=await auditLive({server:f.server,now:()=>now});assert.equal(r.observationVerified,false);assert.equal(r.summary.minimumTtlRemainingLedgers,null);assert.equal(auditExitCode(r),1);
 }
 const f=fake({entry:()=>({latestLedger:seq+1,entries:[]})});assert.equal((await auditLive({server:f.server,now:()=>now})).observationVerified,false);
});
test("malformed results cannot invent expiration or health",()=>{
 const t=targets[1];for(const entries of [undefined,null,{},[{},{}],[{}]])assert.equal(observeEntry(t,{latestLedger:seq,entries}).status,"indeterminate");
 const e=instance(t);e.lastModifiedLedgerSeq=seq+1;assert.equal(observeEntry(t,{latestLedger:seq,entries:[e]}).status,"indeterminate");
});
test("malformed manifest and release pins fail before any RPC",async()=>{
 assert.doesNotThrow(()=>validateAuditPins());
 for(const manifest of [null,{}, {...TESTNET,kitVersion:"0.9.0"},{...TESTNET,referenceCommit:"wrong"},{...TESTNET,contracts:{...TESTNET.contracts,threshold:{...TESTNET.contracts.threshold,hash:"00".repeat(32)}}}]){
  const f=fake(),r=await auditLive({manifest,server:f.server,now:()=>now});assert.deepEqual(f.calls,[]);assert.equal(auditExitCode(r),1);assert.deepEqual(r.errors,["manifest_or_dependency_pin_invalid"]);
 }
});
test("script safety and imports have no transaction paths or startup RPC",()=>{
 const pkg=JSON.parse(readFileSync(new URL("../package.json",import.meta.url)));assert.equal(pkg.scripts["audit:testnet"],"node src/audit.mjs");assert.equal(pkg.scripts["verify:testnet"],"node src/preflight.mjs");
 for(const name of ["audit.mjs","audit-helpers.mjs"]){const src=readFileSync(new URL(`../src/${name}`,import.meta.url),"utf8");assert.doesNotMatch(src,/\b(?:TransactionBuilder|Keypair|sendTransaction|simulateTransaction|submitTransaction|signTransaction|restoreFootprint|extendFootprintTtl|process\.env|secret|operator_local)\b/);}
 const child=spawnSync(process.execPath,["--input-type=module","-e",'globalThis.fetch=()=>{throw Error("network on import")}; await import("./src/audit.mjs");'],{cwd:new URL("..",import.meta.url),encoding:"utf8"});assert.equal(child.status,0,child.stderr);assert.equal(child.stdout,"");
});

test("declared and installed dependency version deviations are fatal",()=>{
 const pins={"smart-account-kit":"0.10.0","@stellar/stellar-sdk":"16.4.1"};
 assert.equal(validateDependencyPins(pins,pins),true);
 for(const name of Object.keys(pins)){
  assert.throws(()=>validateDependencyPins({...pins,[name]:"^"+pins[name]},pins));
  assert.throws(()=>validateDependencyPins(pins,{...pins,[name]:"0.0.0"}));
 }
});
test("network and anchor failures are sanitized and fail closed",async()=>{
 for(const method of ["getNetwork","getLatestLedger"]){
  const f=fake(),server={getNetwork:()=>f.server.getNetwork(),getLatestLedger:()=>f.server.getLatestLedger(),getLedgerEntries:key=>f.server.getLedgerEntries(key)};
  server[method]=async()=>{throw Error("untrusted exception text");};
  const r=await auditLive({server,now:()=>now});assert.equal(auditExitCode(r),1);assert.doesNotMatch(JSON.stringify(r),/untrusted/);
  if(method==="getLatestLedger")assert.equal(r.entries.length,7);
 }
});

test("strict verifier retains its exact 720-ledger boundary",()=>{
 const t=fixtures()[0],policy=targets[1];
 for(const ttl of [0,719,720]){
  assert.throws(()=>validateCodeEntry(code(t,Buffer.from("fixture wasm"),ttl),t.hash,t.size,seq));
  assert.throws(()=>validateContractEntry(instance(policy,ttl),policy.hash,seq));
 }
 assert.equal(validateCodeEntry(code(t,Buffer.from("fixture wasm"),721),t.hash,t.size,seq).ttlRemainingLedgers,721);
 assert.equal(validateContractEntry(instance(policy,721),policy.hash,seq).ttlRemainingLedgers,721);
});
