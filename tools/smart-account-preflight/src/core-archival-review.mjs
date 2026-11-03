import {createHash} from "node:crypto";
import {pathToFileURL} from "node:url";
import {xdr} from "@stellar/stellar-sdk";
import {TESTNET} from "./manifest.mjs";
import {validateAuditPins} from "./audit.mjs";
import {targetsFor,publicTarget,observeEntry,anchorValid,observationConsistent,isLedger,MAX_LEDGER_SPAN,REVIEW_TTL_LEDGERS} from "./audit-helpers.mjs";

export const MAX_RESPONSE_BYTES=4*1024*1024;
const own=(o,k)=>Object.hasOwn(o,k);
const object=o=>o!==null&&typeof o==="object"&&!Array.isArray(o);
const shape=(o,keys)=>object(o)&&Object.keys(o).every(k=>keys.includes(k));
const sha=b=>createHash("sha256").update(b).digest("hex");
// Only the explicitly provisioned query port is allowed. Never infer a port or
// normalize a supplied URL (which would accept alternate hosts, paths or userinfo).
export function validateCoreUrl(url){
 if(url!=="http://127.0.0.1:11627"&&url!=="http://[::1]:11627")throw Error("invalid_core_url");
 return url;
}
export function parseArguments(args){
 if(args.length!==2||args[0]!=="--core-url")throw Error("invalid_arguments");
 return validateCoreUrl(args[1]);
}
export async function queryCore(coreUrl,targets,fetchImpl=globalThis.fetch){
 try{return await requestCore(coreUrl,targets,fetchImpl);}
 catch{throw Error("core_query_unavailable_or_invalid");}
}
async function requestCore(coreUrl,targets,fetchImpl){
 validateCoreUrl(coreUrl);
 const keys=targets.map(t=>t.key.toXDR("base64"));
 if(keys.length!==7||new Set(keys).size!==7||targets.some(t=>!["contractCode","contractData"].includes(t.key.switch().name)))throw Error("invalid_keys");
 const body=new URLSearchParams();
 for(const key of keys)body.append("key",key);
 return fetchJson(`${coreUrl}/getledgerentry`,{
  headers:{"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},body:body.toString()},fetchImpl);
}
async function fetchJson(url,options,fetchImpl){
 const response=await fetchImpl(url,{...options,method:"POST",redirect:"error",signal:AbortSignal.timeout(15000)});
 if(!response.ok||response.redirected||!/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type")??""))throw Error("invalid_core_response");
 const length=response.headers.get("content-length");
 if(length!==null&&(!/^\d+$/.test(length)||Number(length)>MAX_RESPONSE_BYTES))throw Error("oversized_core_response");
 // Bound bytes while streaming, including chunked responses; never buffer first.
 const reader=response.body?.getReader();
 if(!reader)throw Error("invalid_core_response");
 const chunks=[];let size=0;
 try{
  while(true){
   const {done,value}=await reader.read();if(done)break;
   size+=value.byteLength;
   if(size>MAX_RESPONSE_BYTES)throw Error("oversized_core_response");
   chunks.push(Buffer.from(value));
  }
 }catch(error){await reader.cancel().catch(()=>{});throw error;}
 finally{reader.releaseLock();}
 return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks)));
}
// The production RPC adapter exposes only the two required read methods. Both
// destinations share the same bounded transport and reject HTTP redirects.
function publicRpc(fetchImpl){
 async function call(method){
  const payload=await fetchJson(TESTNET.rpcUrl,{headers:{"Content-Type":"application/json","Accept":"application/json"},
   body:JSON.stringify({jsonrpc:"2.0",id:1,method})},fetchImpl);
  if(!object(payload)||payload.jsonrpc!=="2.0"||payload.id!==1||own(payload,"error")||!object(payload.result))throw Error("invalid_public_rpc_response");
  return payload.result;
 }
 return {
  getNetwork:()=>call("getNetwork"),
  async getLatestLedger(){
   const result=await call("getLatestLedger");
   return {...result,headerXdr:xdr.LedgerHeader.fromXDR(result.headerXdr,"base64")};
  }
 };
}
function itemFor(target){
 return {...publicTarget(target),ledgerKeySha256:sha(target.key.toXDR()),identityVerified:false,sha256Verified:target.kind==="code"?false:null};
}
function observeCoreEntry(target,raw,ledger){
 const base={...itemFor(target),observedLedger:ledger};
 if(!shape(raw,["state","entry","liveUntilLedgerSeq"])||!["live","archived","not-found"].includes(raw.state))return {...base,reason:"unexpected_core_entry_shape"};
 if(raw.state==="not-found"){
  if(own(raw,"entry")||own(raw,"liveUntilLedgerSeq"))return {...base,status:"mismatch",reason:"not_found_has_entry_or_ttl"};
  return {...base,status:"not_found",reason:"core_reports_not_found"};
 }
 // Canonical base64 only; LedgerEntry, not LedgerEntryData or CAP draft XDR.
 let decoded;
 try{
  if(typeof raw.entry!=="string"||raw.entry.length===0||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(raw.entry))throw Error();
  decoded=xdr.LedgerEntry.fromXDR(raw.entry,"base64");
  if(decoded.toXDR("base64")!==raw.entry)throw Error();
 }catch{return {...base,reason:"malformed_ledger_entry_xdr"};}
 const data=decoded.data();
 // Reconstruct the *returned* key. Passing the requested key to observeEntry
 // would conceal forged identities in the returned LedgerEntry.
 let key;
 if(data.switch().name==="contractCode")key=xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({hash:data.contractCode().hash()}));
 else if(data.switch().name==="contractData"){
  const d=data.contractData();key=xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({contract:d.contract(),key:d.key(),durability:d.durability()}));
 }else return {...base,status:"mismatch",reason:"entry_type_mismatch"};
 // observeEntry checks identity before TTL. Archived entries use a temporary
 // internal TTL solely to reuse those checks; no synthetic TTL escapes the report.
 const observed=observeEntry(target,{latestLedger:ledger,entries:[{key,val:data,lastModifiedLedgerSeq:decoded.lastModifiedLedgerSeq(),liveUntilLedgerSeq:ledger}]});
 const item={...base,...observed,lastModifiedLedgerSeq:decoded.lastModifiedLedgerSeq(),liveUntilLedgerSeq:null,ttlRemainingLedgers:null};
 if(!["healthy","low_ttl"].includes(observed.status))return item;
 item.identityVerified=true;
 if(target.kind==="code")item.sha256Verified=true;
 const ttl=raw.liveUntilLedgerSeq;
 if(raw.state==="archived"){
  if(own(raw,"liveUntilLedgerSeq")&&ttl!==0)return {...item,status:"mismatch",reason:"archived_has_nonzero_or_invalid_ttl"};
  return {...item,status:"archived",reason:"core_reports_archived_identity_verified"};
 }
 if(!isLedger(ttl)||ttl<ledger)return {...item,status:"indeterminate",reason:"live_ttl_invalid_or_expired"};
 return {...item,status:"live",reason:"core_reports_live_identity_and_ttl_verified",liveUntilLedgerSeq:ttl,ttlRemainingLedgers:ttl-ledger};
}
export function observeCorePayload(targets,payload){
 if(!shape(payload,["entries","ledgerSeq"])||!isLedger(payload.ledgerSeq)||!Array.isArray(payload.entries)||payload.entries.length!==7||targets.length!==7)throw Error("unexpected_core_payload_shape");
 return targets.map((target,index)=>observeCoreEntry(target,payload.entries[index],payload.ledgerSeq));
}
function emptyReport(){
 return {schema_version:1,source:{type:"operator_owned_stellar_core_http_query",trustWarning:"Operator-owned Core observation, not independent consensus proof. Verify Testnet configuration and syncing independently; ledger proximity cannot establish Core network identity.",coreNetworkVerified:false},
  network:{name:"Stellar Testnet",passphrase:TESTNET.networkPassphrase,rpcUrl:TESTNET.rpcUrl,publicRpcVerified:false},
  ledger:null,publicRpcBracket:null,observationVerified:false,
  policy:{maxCoreDistanceLedgers:MAX_LEDGER_SPAN,maxPublicRpcSpanLedgers:MAX_LEDGER_SPAN,maxLedgerAgeSeconds:120,reviewTtlLedgers:REVIEW_TTL_LEDGERS},
  entries:targetsFor(TESTNET).map(itemFor),errors:[],customerWalletReady:false,canDeployCustomerWallet:false,customerWalletCreated:false,credentialRecoveryVerified:false,verifiedFinancialExecution:false,broadcastTransactions:0,transactionsBuilt:0};
}
export function finishReview(report){
 const actions=new Set();
 for(const item of report.entries){
  if(item.status==="archived")actions.add("review_restoration_of_confirmed_archived_entries");
  if(item.status==="live"&&item.ttlRemainingLedgers<=REVIEW_TTL_LEDGERS)actions.add("review_live_ttl_extension");
  if(item.status==="not_found")actions.add("investigate_not_found");
  if(item.status==="mismatch")actions.add("investigate_mismatch");
  if(item.status==="indeterminate")actions.add("retry_or_verify_core_node");
 }
 if(report.errors.length)actions.add("retry_or_verify_core_node");
 const ttls=report.entries.filter(i=>i.status==="live").map(i=>i.ttlRemainingLedgers);
 const allEntriesLive=report.observationVerified&&report.network.publicRpcVerified&&report.errors.length===0&&report.entries.length===7&&report.entries.every(i=>i.status==="live");
 const noTtlReviewNeeded=allEntriesLive&&ttls.length===7&&
  ttls.every(ttl=>Number.isInteger(ttl)&&ttl>REVIEW_TTL_LEDGERS);
 report.summary={allEntriesLive,noTtlReviewNeeded,
  minimumLiveTtlRemainingLedgers:report.observationVerified&&ttls.length?Math.min(...ttls):null,minimumTtlScope:"verified_live_entries_only",actions:[...actions].sort()};
 return report;
}
export const archivalExitCode=report=>report.summary.noTtlReviewNeeded?0:1;
export async function reviewArchival({coreUrl,manifest=TESTNET,server,fetchImpl=globalThis.fetch,now=Date.now}={}){
 const report=emptyReport();
 try{validateCoreUrl(coreUrl);}catch{report.errors.push("explicit_loopback_query_url_required");return finishReview(report);}
 try{validateAuditPins(manifest);}catch{report.errors.push("manifest_or_dependency_pin_invalid");return finishReview(report);}
 const targets=targetsFor(TESTNET);
 server??=publicRpc(fetchImpl);
 let start,end,payload;
 try{
  const network=await server.getNetwork();
  if(network?.passphrase!==TESTNET.networkPassphrase){report.errors.push("wrong_testnet_network");return finishReview(report);}
  report.network.publicRpcVerified=true;
  start=await server.getLatestLedger();
  if(!anchorValid(start,now())){report.errors.push("invalid_start_ledger_anchor");return finishReview(report);}
 }catch{report.errors.push("public_rpc_observation_failed");return finishReview(report);}
 try{payload=await queryCore(coreUrl,targets,fetchImpl);report.entries=observeCorePayload(targets,payload);report.ledger=payload.ledgerSeq;}
 catch{report.errors.push("core_query_unavailable_or_invalid");}
 try{end=await server.getLatestLedger();}catch{report.errors.push("public_rpc_observation_failed");}
 // Validate the RPC bracket independently, then permit Core at most 12 ledgers
 // behind its first anchor or ahead of its last anchor. Core has no header here.
 report.observationVerified=report.ledger!==null&&observationConsistent(start,end,[],now())&&
  report.ledger>=start.sequence-MAX_LEDGER_SPAN&&report.ledger<=end.sequence+MAX_LEDGER_SPAN;
 if(report.observationVerified)report.publicRpcBracket={first:start.sequence,last:end.sequence};
 else{
  report.errors.push("stale_or_inconsistent_core_or_rpc_ledger");
  report.entries=report.entries.map(item=>({...item,status:item.status==="mismatch"?"mismatch":"indeterminate",reason:item.status==="mismatch"?item.reason:"unverified_ledger_context",identityVerified:false,sha256Verified:item.kind==="code"?false:null,liveUntilLedgerSeq:null,ttlRemainingLedgers:null}));
 }
 return finishReview(report);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 let coreUrl;
 try{coreUrl=parseArguments(process.argv.slice(2));}catch{
  const report=emptyReport();report.errors.push("explicit_loopback_query_url_required");
  console.log(JSON.stringify(finishReview(report),null,2));process.exitCode=1;
 }
 if(coreUrl)reviewArchival({coreUrl}).then(report=>{console.log(JSON.stringify(report,null,2));process.exitCode=archivalExitCode(report);}).catch(()=>{
  const report=emptyReport();report.errors.push("archival_review_failed");
  console.log(JSON.stringify(finishReview(report),null,2));process.exitCode=1;
 });
}
