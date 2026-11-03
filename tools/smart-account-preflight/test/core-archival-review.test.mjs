import {test} from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {xdr} from "@stellar/stellar-sdk";
import {TESTNET} from "../src/manifest.mjs";
import {targetsFor,REVIEW_TTL_LEDGERS} from "../src/audit-helpers.mjs";
import {validateCoreUrl,parseArguments,queryCore,observeCorePayload,reviewArchival,finishReview,archivalExitCode,MAX_RESPONSE_BYTES} from "../src/core-archival-review.mjs";
const coreUrl="http://127.0.0.1:11627",seq=5523276,now=1793620800000;
const hash=b=>createHash("sha256").update(b).digest("hex");
const pinned=targetsFor(TESTNET);
// Synthetic code fixtures exercise success without weakening the production pins.
const targets=pinned.map(t=>{
 if(t.kind!=="code")return t;
 const bytes=Buffer.from(`fixture ${t.name}`),h=hash(bytes);
 return {...t,hash:h,size:bytes.length,bytes,key:xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({hash:Buffer.from(h,"hex")}))};
});
function anchor(sequence=seq,time=now/1000){
 const zero=Buffer.alloc(32);
 const header=new xdr.LedgerHeader({ledgerVersion:25,previousLedgerHash:zero,
  scpValue:new xdr.StellarValue({txSetHash:zero,closeTime:xdr.Uint64.fromString(String(time)),upgrades:[],ext:xdr.StellarValueExt.stellarValueBasic()}),
  txSetResultHash:zero,bucketListHash:zero,ledgerSeq:sequence,totalCoins:xdr.Int64.fromString("0"),feePool:xdr.Int64.fromString("0"),inflationSeq:0,idPool:xdr.Uint64.fromString("0"),baseFee:100,baseReserve:1,maxTxSetSize:1,skipList:[zero,zero,zero,zero],ext:new xdr.LedgerHeaderExt(0)});
 return {id:hash(header.toXDR()),sequence,closeTime:String(time),headerXdr:header};
}
function entry(t,{state="live",ttl=seq+200000,lastModified=seq-1,bytes=t.bytes,embedded=t.hash,wasm=t.hash}={}){
 let data;
 if(t.kind==="code")data=xdr.LedgerEntryData.contractCode(new xdr.ContractCodeEntry({ext:new xdr.ContractCodeEntryExt(0),hash:Buffer.from(embedded,"hex"),code:bytes??Buffer.from("invalid pinned fixture")}));
 else{
  const d=t.key.contractData();
  data=xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({ext:new xdr.ExtensionPoint(0),contract:d.contract(),key:d.key(),durability:d.durability(),val:xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({executable:xdr.ContractExecutable.contractExecutableWasm(Buffer.from(wasm,"hex")),storage:[]}))}));
 }
 return {state,entry:new xdr.LedgerEntry({lastModifiedLedgerSeq:lastModified,data,ext:new xdr.LedgerEntryExt(0)}).toXDR("base64"),liveUntilLedgerSeq:ttl};
}
const payload=(ts=targets)=>({entries:ts.map(t=>entry(t)),ledgerSeq:seq});
const observe=(p=payload())=>observeCorePayload(targets,p);
const response=p=>new Response(JSON.stringify(p),{headers:{"Content-Type":"application/json"}});
function fake({p={ledgerSeq:seq,entries:pinned.map(()=>({state:"not-found"}))},network=TESTNET.networkPassphrase,anchors=[anchor(),anchor()],failure}={}){
 const calls=[];
 const server=new Proxy({async getNetwork(){calls.push("getNetwork");if(failure==="network")throw Error("PRIVATE injected error");return {passphrase:network};},async getLatestLedger(){calls.push("getLatestLedger");if(failure==="anchor")throw Error("PRIVATE injected error");return anchors.shift();}},{get(o,k){assert.ok(Object.hasOwn(o,k),`Forbidden API ${String(k)}`);return o[k];}});
 const fetchImpl=async(url,options)=>{calls.push({url,options});if(failure==="core")throw Error("PRIVATE injected error");return response(p);};
 return {calls,server,fetchImpl};
}
const run=async(options={})=>{const f=fake(options);return {f,r:await reviewArchival({coreUrl,now:()=>now,server:f.server,fetchImpl:f.fetchImpl})};};

test("seven positional live XDR fixtures validate identity, SHA, account size and TTL deterministically",()=>{
 const items=observe();assert.equal(items.length,7);assert.ok(items.every(i=>i.status==="live"&&i.identityVerified));
 assert.ok(items.filter(i=>i.kind==="code").every(i=>i.sha256Verified&&i.computedWasmSha256===i.expectedWasmHash));
 assert.deepEqual(items,observe());assert.ok(items.every(i=>/^[a-f0-9]{64}$/.test(i.ledgerKeySha256)));
 const r=finishReview({entries:items,network:{publicRpcVerified:true},observationVerified:true,errors:[]});
 assert.equal(archivalExitCode(r),0);assert.equal(r.summary.minimumLiveTtlRemainingLedgers,200000);
});
test("all live entries with low TTL still fail the operator release review",()=>{
 const items=observe();
 items[0].ttlRemainingLedgers=REVIEW_TTL_LEDGERS;
 const r=finishReview({entries:items,network:{publicRpcVerified:true},observationVerified:true,errors:[]});
 assert.equal(r.summary.allEntriesLive,true);
 assert.equal(r.summary.noTtlReviewNeeded,false);
 assert.deepEqual(r.summary.actions,["review_live_ttl_extension"]);
 assert.equal(archivalExitCode(r),1);
 items[0].ttlRemainingLedgers=REVIEW_TTL_LEDGERS+1;
 const safe=finishReview({entries:items,network:{publicRpcVerified:true},observationVerified:true,errors:[]});
 assert.equal(safe.summary.noTtlReviewNeeded,true);
 assert.equal(archivalExitCode(safe),0);
});

test("positional code and instance order swaps fail identity checks",()=>{
 for(const [a,b] of [[0,2],[1,3],[0,1]]){
  const p=payload();[p.entries[a],p.entries[b]]=[p.entries[b],p.entries[a]];
  const items=observe(p);assert.equal(items[a].status,"mismatch");assert.equal(items[b].status,"mismatch");
 }
});
test("extra and missing entries, CAP draft fields and unexpected envelope shapes fail closed",()=>{
 for(const p of [null,[],{}, {...payload(),entries:payload().entries.slice(1)},{...payload(),entries:[...payload().entries,entry(targets[0])]},{...payload(),extra:true}, {...payload(),ledgerSeq:"5523276"}])assert.throws(()=>observe(p));
 for(const raw of [{state:"live",e:entry(targets[0]).entry,ttl:seq+1},{...entry(targets[0]),key:"forged"},{state:"unknown"},null]){
  const p=payload();p.entries[0]=raw;assert.equal(observe(p)[0].status,"indeterminate");
 }
});
test("malformed, noncanonical and wrong XDR types cannot pass",()=>{
 for(const raw of ["garbage","",null,entry(targets[0]).entry+"\n",targets[0].key.toXDR("base64"),entry(targets[0]).entry+"AAAA"]){
  const p=payload();p.entries[0].entry=raw;assert.equal(observe(p)[0].status,"indeterminate");
 }
});
test("computed code SHA, embedded code hash and account byte length independently checked",()=>{
 for(const options of [{bytes:Buffer.from("tampered")},{embedded:"00".repeat(32)}]){
  const p=payload();p.entries[0]=entry(targets[0],options);assert.equal(observe(p)[0].status,"mismatch");assert.equal(observe(p)[0].sha256Verified,false);
 }
 const ts=[{...targets[0],size:999},...targets.slice(1)];assert.equal(observeCorePayload(ts,payload())[0].status,"mismatch");
});
test("instance executable and forged contract, key or durability identities are rejected",()=>{
 let p=payload();p.entries[1]=entry(targets[1],{wasm:"00".repeat(32)});assert.equal(observe(p)[1].status,"mismatch");
 for(const mutate of [d=>d.contract(targets[3].key.contractData().contract()),d=>d.key(xdr.ScVal.scvU32(1)),d=>d.durability(xdr.ContractDataDurability.temporary()),d=>d.val(xdr.ScVal.scvU32(1))]){
  p=payload();const le=xdr.LedgerEntry.fromXDR(p.entries[1].entry,"base64");mutate(le.data().contractData());p.entries[1].entry=le.toXDR("base64");
  assert.equal(observe(p)[1].status,"mismatch");assert.equal(observe(p)[1].identityVerified,false);
 }
});
test("lastModified must be a positive uint32 no later than Core ledger",()=>{
 for(const lastModified of [0,seq+1]){
  const p=payload();p.entries[1]=entry(targets[1],{lastModified});assert.equal(observe(p)[1].status,"indeterminate");
 }
});
test("live positive TTL range required; zero, absent, null and past TTL never count as archived",()=>{
 for(const ttl of [0,null,undefined,-1,seq-1,"9999999",2**32,1.5]){
  const p=payload();p.entries[1].liveUntilLedgerSeq=ttl;
  if(ttl===undefined)delete p.entries[1].liveUntilLedgerSeq;
  const item=observe(p)[1];assert.equal(item.status,"indeterminate");assert.equal(item.ttlRemainingLedgers,null);
 }
 const p=payload();p.entries[1].liveUntilLedgerSeq=seq;assert.equal(observe(p)[1].status,"live");assert.equal(observe(p)[1].ttlRemainingLedgers,0);
});
test("archived needs verified XDR and absent or zero TTL, distinct from not-found",()=>{
 for(const ttl of [0,undefined]){
  const p=payload();p.entries[0]=entry(targets[0],{state:"archived",ttl:0});if(ttl===undefined)delete p.entries[0].liveUntilLedgerSeq;
  p.entries[1]={state:"not-found"};const items=observe(p);
  assert.equal(items[0].status,"archived");assert.equal(items[0].identityVerified,true);assert.equal(items[0].ttlRemainingLedgers,null);assert.equal(items[1].status,"not_found");
 }
 for(const ttl of [1,null,-1,"0"]){const p=payload();p.entries[0]=entry(targets[0],{state:"archived",ttl});assert.equal(observe(p)[0].status,"mismatch");}
 const p=payload();p.entries[0]={state:"archived"};assert.equal(observe(p)[0].status,"indeterminate");
 p.entries[0]=entry(targets[0],{state:"archived",ttl:0,bytes:Buffer.from("bad")});assert.equal(observe(p)[0].status,"mismatch");
});
test("not-found must omit both entry and TTL, including null/zero fields",()=>{
 for(const extra of [{entry:null},{entry:entry(targets[0]).entry},{liveUntilLedgerSeq:0},{liveUntilLedgerSeq:null}]){
  const p=payload();p.entries[0]={state:"not-found",...extra};assert.equal(observe(p)[0].status,"mismatch");
 }
});
test("wrong public network or malformed manifest fails before Core or ledger access",async()=>{
 const {f,r}=await run({network:"Public Global Stellar Network ; September 2015"});assert.deepEqual(f.calls,["getNetwork"]);assert.equal(archivalExitCode(r),1);
 const bad=fake();const invalid=await reviewArchival({coreUrl,manifest:{...TESTNET,referenceCommit:"bad"},server:bad.server,fetchImpl:bad.fetchImpl});assert.deepEqual(bad.calls,[]);assert.equal(archivalExitCode(invalid),1);
});
test("stale/ahead Core ledger rejected outside 12-ledger bracket and exact boundaries accepted",async()=>{
 for(const offset of [-13,13]){
  const {r}=await run({p:{entries:pinned.map(()=>({state:"not-found"})),ledgerSeq:seq+offset}});
  assert.equal(r.observationVerified,false);assert.ok(r.entries.every(i=>i.status==="indeterminate"));assert.equal(r.summary.minimumLiveTtlRemainingLedgers,null);
 }
 for(const offset of [-12,12]){const {r}=await run({p:{entries:pinned.map(()=>({state:"not-found"})),ledgerSeq:seq+offset}});assert.equal(r.observationVerified,true);}
});
test("fresh canonical public RPC bracket required with bounded span and matching equal-sequence hashes",async()=>{
 for(const anchors of [[anchor(seq,now/1000-121),anchor()],[anchor(),anchor(seq,now/1000+31)],[anchor(),anchor(seq-1)],[anchor(),anchor(seq+13)],[anchor(),anchor(seq,now/1000-1)],[anchor(),{...anchor(),id:"00".repeat(32)}]]){
  const {r}=await run({anchors});assert.equal(r.observationVerified,false);assert.equal(archivalExitCode(r),1);
 }
});
test("only literal loopback query URL with explicit safe port is accepted",async()=>{
 for(const url of [undefined,"http://localhost:11627","https://127.0.0.1:11627","http://127.0.0.1","http://127.0.0.1:11626","http://127.0.0.1:11627/","http://127.0.0.1:11627/info","http://127.0.0.1:11627?key=x","http://127.0.0.1:11627#x","http://u:p@127.0.0.1:11627","http://127.1:11627","http://2130706433:11627","http://example.com:11627","http://[::1]:11626"]){
  assert.throws(()=>validateCoreUrl(url));const f=fake();const r=await reviewArchival({coreUrl:url,server:f.server,fetchImpl:f.fetchImpl});assert.deepEqual(f.calls,[]);assert.equal(archivalExitCode(r),1);
 }
 assert.equal(validateCoreUrl("http://[::1]:11627"),"http://[::1]:11627");
 assert.equal(parseArguments(["--core-url",coreUrl]),coreUrl);
 for(const args of [[],[coreUrl],["--core-url",coreUrl,"--extra"],["--core-url",coreUrl,"--core-url",coreUrl]])assert.throws(()=>parseArguments(args));
});
test("local mocked HTTP request is exactly POST /getledgerentry with seven repeated keys and no other network calls",async()=>{
 const {f,r}=await run();const requests=f.calls.filter(c=>typeof c==="object");assert.equal(requests.length,1);
 const {url,options}=requests[0];const request=new Request(url,options);
 assert.equal(request.url,`${coreUrl}/getledgerentry`);assert.equal(request.method,"POST");assert.equal(request.redirect,"error");assert.ok(options.signal instanceof AbortSignal);
 assert.equal(request.headers.get("Content-Type"),"application/x-www-form-urlencoded");
 const form=new URLSearchParams(await request.text());assert.deepEqual([...form.keys()],Array(7).fill("key"));assert.deepEqual(form.getAll("key"),pinned.map(t=>t.key.toXDR("base64")));
 assert.deepEqual(f.calls.filter(c=>typeof c==="string"),["getNetwork","getLatestLedger","getLatestLedger"]);
 assert.equal(r.entries.length,7);assert.equal(r.source.coreNetworkVerified,false);assert.equal(archivalExitCode(r),1);
});
test("redirects, non-JSON, HTTP errors, huge fixed/chunked bodies and invalid JSON rejected",async()=>{
 const responses=[new Response(null,{status:302,headers:{Location:"http://127.0.0.1:11626/info"}}),new Response("{}",{headers:{"Content-Type":"text/html"}}),new Response("{}",{status:500,headers:{"Content-Type":"application/json"}}),new Response("{}",{headers:{"Content-Type":"application/json","Content-Length":String(MAX_RESPONSE_BYTES+1)}}),new Response(" ".repeat(MAX_RESPONSE_BYTES+1),{headers:{"Content-Type":"application/json"}}),new Response("not json",{headers:{"Content-Type":"application/json"}})];
 for(const res of responses)await assert.rejects(queryCore(coreUrl,pinned,async()=>res));
 await assert.rejects(queryCore(coreUrl,pinned,async(_u,o)=>{assert.equal(o.redirect,"error");throw Error("redirect blocked");}));
});
test("no Core service and all thrown API errors produce sanitized fail-closed JSON",async()=>{
 for(const failure of ["core","network","anchor"]){const {r}=await run({failure});assert.equal(archivalExitCode(r),1);assert.doesNotMatch(JSON.stringify(r),/PRIVATE/);assert.ok(r.summary.actions.includes("retry_or_verify_core_node"));}
});
test("mixed states yield distinct review-only actions, valid live minimum, and fixed safety flags",async()=>{
 const p={ledgerSeq:seq,entries:pinned.map(()=>({state:"not-found"}))};
 p.entries[1]=entry(pinned[1],{state:"archived",ttl:0});p.entries[3]=entry(pinned[3],{ttl:seq+REVIEW_TTL_LEDGERS});p.entries[5]=entry(pinned[5],{wasm:"00".repeat(32)});
 const {r}=await run({p});assert.deepEqual(r.summary.actions,["investigate_mismatch","investigate_not_found","review_live_ttl_extension","review_restoration_of_confirmed_archived_entries"]);
 assert.equal(r.summary.minimumLiveTtlRemainingLedgers,REVIEW_TTL_LEDGERS);assert.equal(archivalExitCode(r),1);
 for(const key of ["customerWalletReady","canDeployCustomerWallet","customerWalletCreated","credentialRecoveryVerified","verifiedFinancialExecution"])assert.equal(r[key],false);
 for(const key of ["broadcastTransactions","transactionsBuilt"])assert.equal(r[key],0);
 assert.equal(JSON.stringify(r),JSON.stringify((await run({p})).r));
});
test("no transaction API, credentials or import-time network and script wiring stays read-only",()=>{
 const src=readFileSync(new URL("../src/core-archival-review.mjs",import.meta.url),"utf8");
 assert.doesNotMatch(src,/\b(?:TransactionBuilder|Keypair|sendTransaction|simulateTransaction|submitTransaction|signTransaction|restoreFootprint|extendFootprintTtl|process\.env|operator_local)\b/);
 const pkg=JSON.parse(readFileSync(new URL("../package.json",import.meta.url)));assert.equal(pkg.scripts["review:archival"],"node src/core-archival-review.mjs");
 const child=spawnSync(process.execPath,["--input-type=module","-e",'globalThis.fetch=()=>{throw Error("network on import")}; await import("./src/core-archival-review.mjs");'],{cwd:new URL("..",import.meta.url),encoding:"utf8"});assert.equal(child.status,0,child.stderr);assert.equal(child.stdout,"");
});
test("missing/extra response entries and invalid envelopes cannot leave partial verified findings",async()=>{
 for(const p of [{ledgerSeq:seq,entries:[]},{ledgerSeq:seq,entries:[...pinned.map(()=>({state:"not-found"})),{state:"not-found"}]},{ledgerSeq:0,entries:pinned.map(()=>({state:"not-found"}))},{ledgerSeq:seq,entries:pinned.map(()=>({state:"not-found"})),network:"Testnet"}]){
  const {r}=await run({p});assert.equal(archivalExitCode(r),1);assert.equal(r.entries.length,7);assert.ok(r.entries.every(i=>i.status==="indeterminate"));assert.ok(r.summary.actions.includes("retry_or_verify_core_node"));
 }
});
test("query helper sanitizes failures and rejects duplicate keys or TTL keys before fetch",async()=>{
 await assert.rejects(queryCore(coreUrl,pinned,async()=>{throw Error("PRIVATE userinfo injected");}),{message:"core_query_unavailable_or_invalid"});
 for(const ts of [[...pinned.slice(0,6),pinned[0]],[{...pinned[0],key:xdr.LedgerKey.ttl(new xdr.LedgerKeyTtl({keyHash:Buffer.alloc(32)}))},...pinned.slice(1)]]){
  let calls=0;await assert.rejects(queryCore(coreUrl,ts,async()=>{calls++;throw Error();}));assert.equal(calls,0);
 }
});
test("default transport makes only pinned read RPC calls and one local Core POST, all bounded and redirect-blocked",async()=>{
 const calls=[];
 const fetchImpl=async(url,options)=>{
  assert.equal(options.method,"POST");assert.equal(options.redirect,"error");assert.ok(options.signal instanceof AbortSignal);
  if(url===`${coreUrl}/getledgerentry`){calls.push("core");return response({ledgerSeq:seq,entries:pinned.map(()=>({state:"not-found"}))});}
  assert.equal(url,TESTNET.rpcUrl);
  const request=JSON.parse(options.body);assert.equal(request.jsonrpc,"2.0");assert.equal(request.id,1);
  calls.push(request.method);let result;
  if(request.method==="getNetwork")result={passphrase:TESTNET.networkPassphrase};
  else{assert.equal(request.method,"getLatestLedger");const a=anchor();result={...a,headerXdr:a.headerXdr.toXDR("base64")};}
  return response({jsonrpc:"2.0",id:1,result});
 };
 const r=await reviewArchival({coreUrl,fetchImpl,now:()=>now});
 assert.deepEqual(calls,["getNetwork","getLatestLedger","core","getLatestLedger"]);
 assert.equal(r.observationVerified,true);assert.equal(r.network.publicRpcVerified,true);assert.equal(archivalExitCode(r),1);
});
test("default public RPC transport rejects redirects, bad envelopes and forged headers before Core access",async()=>{
 for(const bad of [{jsonrpc:"2.0",id:2,result:{passphrase:TESTNET.networkPassphrase}},{jsonrpc:"2.0",id:1,error:{message:"PRIVATE"}},{jsonrpc:"2.0",id:1,result:null}]){
  let count=0;const r=await reviewArchival({coreUrl,fetchImpl:async(url)=>{assert.equal(url,TESTNET.rpcUrl);count++;return response(bad);}});
  assert.equal(count,1);assert.equal(archivalExitCode(r),1);assert.doesNotMatch(JSON.stringify(r),/PRIVATE/);
 }
 let count=0;const r=await reviewArchival({coreUrl,fetchImpl:async(url,o)=>{
  assert.equal(url,TESTNET.rpcUrl);assert.equal(o.redirect,"error");count++;
  return count===1?response({jsonrpc:"2.0",id:1,result:{passphrase:TESTNET.networkPassphrase}}):response({jsonrpc:"2.0",id:1,result:{...anchor(),headerXdr:"garbage"}});
 }});assert.equal(count,2);assert.equal(archivalExitCode(r),1);
});
