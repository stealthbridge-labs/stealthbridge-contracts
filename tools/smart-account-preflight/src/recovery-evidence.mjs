import {constants, lstatSync, openSync, fstatSync, readSync, closeSync} from "node:fs";
import {createHash} from "node:crypto";
import {pathToFileURL} from "node:url";
import {TESTNET} from "./manifest.mjs";
import {validateAuditPins} from "./audit.mjs";
import {targetsFor, isLedger, summarize, REVIEW_TTL_LEDGERS, STRICT_MARGIN_LEDGERS, MAX_LEDGER_SPAN} from "./audit-helpers.mjs";
import {finishReview} from "./core-archival-review.mjs";

export const MAX_FILE_BYTES=512*1024;
const MAX_SNAPSHOT_GAP=24;
const object=o=>o!==null&&typeof o==="object"&&!Array.isArray(o);
const own=(o,k)=>Object.hasOwn(o,k);
const requireValid=condition=>{if(!condition)throw Error("invalid_evidence");};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function exactKeys(value,keys){requireValid(object(value)&&Object.keys(value).length===keys.length&&keys.every(k=>own(value,k)));}
function envelope(r,core){
 exactKeys(r,["schema_version","network","observationVerified","policy","entries","errors","canDeployCustomerWallet","customerWalletCreated","credentialRecoveryVerified","verifiedFinancialExecution","broadcastTransactions","transactionsBuilt","summary",...(core?["source","ledger","publicRpcBracket","customerWalletReady"]:["observedLedger","ledgerSpan"])]);
 const network=core?{name:"Stellar Testnet",passphrase:TESTNET.networkPassphrase,rpcUrl:TESTNET.rpcUrl,publicRpcVerified:true}:{name:"Stellar Testnet",rpcUrl:TESTNET.rpcUrl,expectedPassphrase:TESTNET.networkPassphrase,verified:true};
 summaryMatches(r.network,network);
 summaryMatches(r.policy,core?{maxCoreDistanceLedgers:MAX_LEDGER_SPAN,maxPublicRpcSpanLedgers:MAX_LEDGER_SPAN,maxLedgerAgeSeconds:120,reviewTtlLedgers:REVIEW_TTL_LEDGERS}:{reviewTtlLedgers:REVIEW_TTL_LEDGERS,strictVerifierMarginLedgers:STRICT_MARGIN_LEDGERS,maxLedgerSpan:MAX_LEDGER_SPAN,maxLedgerAgeSeconds:120});
}
function summaryMatches(actual,expected){
 requireValid(object(actual)&&Object.keys(actual).length===Object.keys(expected).length);
 for(const [key,value] of Object.entries(expected))requireValid(same(actual[key],value));
}
function bracket(b){return object(b)&&Object.keys(b).length===2&&isLedger(b.first)&&isLedger(b.last)&&b.first<=b.last&&b.last-b.first<=MAX_LEDGER_SPAN;}
const inBracket=(n,b)=>isLedger(n)&&n>=b.first&&n<=b.last;
const distance=(n,b)=>Math.max(b.first-n,n-b.last,0);
function disabledClaims(r){
 for(const k of ["canDeployCustomerWallet","customerWalletReady","customerWalletCreated","credentialRecoveryVerified","financialExecution","verifiedFinancialExecution","independentCoreTrustEstablished"]){
  if(own(r,k))requireValid(r[k]===false);
 }
 for(const k of ["transactionsBuilt","broadcastTransactions"])if(own(r,k))requireValid(r[k]===0);
 requireValid(Array.isArray(r.errors)&&r.errors.length===0);
}
const fields=["name","kind","contractId","expectedWasmHash","observedLedger","liveUntilLedgerSeq","ttlRemainingLedgers","status","reason","observedWasmHash","computedWasmSha256","wasmSize"];
function identity(item,t,core){
 requireValid(object(item)&&Object.keys(item).every(k=>[...fields,...(core?["ledgerKeySha256","identityVerified","sha256Verified","lastModifiedLedgerSeq"]:[])].includes(k)));
 requireValid(typeof item.reason==="string"&&item.reason.length>0);
 requireValid(item.name===t.name&&item.kind===t.kind&&item.expectedWasmHash===t.hash);
 requireValid(t.id?item.contractId===t.id:!own(item,"contractId"));
 for(const k of ["observedWasmHash","computedWasmSha256"])if(own(item,k))requireValid(item[k]===t.hash);
 if(own(item,"wasmSize"))requireValid(Number.isSafeInteger(item.wasmSize)&&item.wasmSize>0&&(t.size===undefined||item.wasmSize===t.size));
 if(core){
  requireValid(item.ledgerKeySha256===createHash("sha256").update(t.key.toXDR()).digest("hex"));
  requireValid(typeof item.identityVerified==="boolean"&&(t.kind==="code"?typeof item.sha256Verified==="boolean":item.sha256Verified===null));
  if(own(item,"lastModifiedLedgerSeq"))requireValid(isLedger(item.lastModifiedLedgerSeq)&&item.lastModifiedLedgerSeq<=item.observedLedger);
 }
}
function verifiedIdentity(i,t,core){
 requireValid(i.observedWasmHash===t.hash);
 if(t.kind==="code")requireValid(i.computedWasmSha256===t.hash&&Number.isSafeInteger(i.wasmSize)&&i.wasmSize>0&&(!core||i.sha256Verified===true));
 else requireValid(!own(i,"computedWasmSha256")&&!own(i,"wasmSize"));
 if(core)requireValid(isLedger(i.lastModifiedLedgerSeq)&&i.lastModifiedLedgerSeq<=i.observedLedger);
 if(core)requireValid(i.identityVerified===true);
}
function liveTtl(i){
 requireValid(isLedger(i.liveUntilLedgerSeq)&&i.liveUntilLedgerSeq>=i.observedLedger&&Number.isInteger(i.ttlRemainingLedgers)&&i.ttlRemainingLedgers===i.liveUntilLedgerSeq-i.observedLedger);
}
function noTtl(i){requireValid(i.liveUntilLedgerSeq===null&&i.ttlRemainingLedgers===null);}
function entries(r,targets,core){
 requireValid(Array.isArray(r.entries)&&r.entries.length===targets.length);
 r.entries.forEach((i,index)=>{
  const t=targets[index];identity(i,t,core);
  requireValid(core?i.observedLedger===r.ledger:inBracket(i.observedLedger,r.ledgerSpan));
  if(core){
   requireValid(["live","archived","not_found","mismatch","indeterminate"].includes(i.status));
   if(["live","archived"].includes(i.status)){
    verifiedIdentity(i,t,true);
    requireValid(i.reason===(i.status==="live"?"core_reports_live_identity_and_ttl_verified":"core_reports_archived_identity_verified"));
    if(i.status==="live")liveTtl(i);else noTtl(i);
   }else{
    noTtl(i);
    if(i.status==="not_found")requireValid(i.reason==="core_reports_not_found"&&!i.identityVerified&&i.sha256Verified!==true&&!["observedWasmHash","computedWasmSha256","wasmSize","lastModifiedLedgerSeq"].some(k=>own(i,k)));
   }
  }else{
   requireValid(["healthy","low_ttl","unavailable_live_entry","mismatch","indeterminate"].includes(i.status));
   if(["healthy","low_ttl"].includes(i.status)){
    verifiedIdentity(i,t,false);liveTtl(i);requireValid(i.reason==="identity_and_live_ttl_observed");
    requireValid((i.status==="low_ttl")===(i.ttlRemainingLedgers<=REVIEW_TTL_LEDGERS));
   }else if(i.status==="unavailable_live_entry"){
    requireValid(["live_only_absence_archive_or_nonexistent_ambiguous","rpc_zero_ttl_no_verified_live_entry","reported_ttl_precedes_observation_live_state_unconfirmed"].includes(i.reason));
    if(i.reason==="live_only_absence_archive_or_nonexistent_ambiguous")requireValid(i.liveUntilLedgerSeq===null&&!["observedWasmHash","computedWasmSha256","wasmSize"].some(k=>own(i,k)));
    else verifiedIdentity(i,t,false);
    if(i.reason==="rpc_zero_ttl_no_verified_live_entry")requireValid(i.liveUntilLedgerSeq===null);
    if(i.reason==="reported_ttl_precedes_observation_live_state_unconfirmed")requireValid(isLedger(i.liveUntilLedgerSeq)&&i.liveUntilLedgerSeq<i.observedLedger);
    // A positive past expiration is historical only; it never becomes live TTL.
    requireValid(i.ttlRemainingLedgers===null&&(i.liveUntilLedgerSeq===null||(isLedger(i.liveUntilLedgerSeq)&&i.liveUntilLedgerSeq<i.observedLedger)));
   }else if(i.liveUntilLedgerSeq===null)requireValid(i.ttlRemainingLedgers===null);
   else if(isLedger(i.liveUntilLedgerSeq)&&i.liveUntilLedgerSeq<i.observedLedger)requireValid(i.ttlRemainingLedgers===null);
   else liveTtl(i);
  }
 });
}
function auditValid(r,targets){
 envelope(r,false);
 requireValid(object(r)&&r.schema_version===1&&r.network?.expectedPassphrase===TESTNET.networkPassphrase&&r.network.verified===true&&r.observationVerified===true);
 requireValid(bracket(r.ledgerSpan)&&r.observedLedger===r.ledgerSpan.last);disabledClaims(r);entries(r,targets,false);
 summaryMatches(r.summary,summarize(r.entries,true));
}
function coreValid(r,targets){
 envelope(r,true);
 exactKeys(r.source,["type","trustWarning","coreNetworkVerified"]);
 requireValid(r.source.trustWarning==="Operator-owned Core observation, not independent consensus proof. Verify Testnet configuration and syncing independently; ledger proximity cannot establish Core network identity.");
 requireValid(object(r)&&r.schema_version===1&&r.source?.type==="operator_owned_stellar_core_http_query"&&r.source.coreNetworkVerified===false);
 requireValid(r.network?.passphrase===TESTNET.networkPassphrase&&r.network.publicRpcVerified===true&&r.observationVerified===true);
 requireValid(isLedger(r.ledger)&&bracket(r.publicRpcBracket)&&distance(r.ledger,r.publicRpcBracket)<=MAX_LEDGER_SPAN);
 disabledClaims(r);entries(r,targets,true);
 summaryMatches(r.summary,finishReview({...r}).summary);
}
export function parseArguments(args){
 requireValid(args.length===4);
 const paths={};
 for(let n=0;n<4;n+=2){
  requireValid(["--audit-json","--core-json"].includes(args[n])&&!own(paths,args[n])&&typeof args[n+1]==="string"&&args[n+1].length>0&&!args[n+1].startsWith("--"));
  paths[args[n]]=args[n+1];
 }
 requireValid(own(paths,"--audit-json")&&own(paths,"--core-json"));
 return {auditPath:paths["--audit-json"],corePath:paths["--core-json"]};
}
export function readEvidenceFile(path){
 // Reject special files before open; O_NOFOLLOW closes the leaf-symlink race,
 // O_NONBLOCK prevents a raced FIFO from blocking. Read at most limit + 1 bytes.
 const before=lstatSync(path);requireValid(before.isFile()&&(before.mode&0o444)!==0&&before.size<=MAX_FILE_BYTES);
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const stat=fstatSync(fd);requireValid(stat.isFile()&&stat.size<=MAX_FILE_BYTES&&stat.dev===before.dev&&stat.ino===before.ino);
  const bytes=Buffer.alloc(MAX_FILE_BYTES+1);let size=0,n;
  while(size<bytes.length&&(n=readSync(fd,bytes,size,bytes.length-size,null))>0)size+=n;
  const after=fstatSync(fd);
  requireValid(size<=MAX_FILE_BYTES&&size===stat.size&&after.size===stat.size&&after.mtimeMs===stat.mtimeMs&&after.ctimeMs===stat.ctimeMs);
  return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes.subarray(0,size)));
 }finally{closeSync(fd);}
}
function emptyReport(){
 return {schema_version:1,result:"blocked",observedLedgers:{audit:null,auditSpan:null,core:null,corePublicRpcBracket:null},
  source:{type:"operator_owned",method:"offline_report_reconciliation",coreNetworkVerified:false,trustCaveat:"Input reports are claims, not authenticated proofs. Core is operator-owned; independently verify its Testnet network, history/quorum configuration and sync. Ledger proximity and XDR identity checks do not establish independent Core trust."},
  policy:{executionEnabled:false,maxInputBytes:MAX_FILE_BYTES,maxLedgerSpan:MAX_LEDGER_SPAN,maxSnapshotGapLedgers:MAX_SNAPSHOT_GAP,reviewTtlLedgers:REVIEW_TTL_LEDGERS,historicalTtlEstablishesArchival:false,inputAuthenticityEstablished:false,currentFreshnessEstablished:false},
  entries:targetsFor(TESTNET).map(t=>({name:t.name,kind:t.kind,...(t.id?{contractId:t.id}:{}),expectedWasmHash:t.hash,reviewState:"insufficient_evidence",publicTtl:null,coreTtl:null})),
  errors:[],summary:{counts:{},reviewTasks:[]},userPermissionRequired:true,independentCoreTrustEstablished:false,canDeployCustomerWallet:false,customerWalletReady:false,customerWalletCreated:false,credentialRecoveryVerified:false,vaultEnabled:false,privacyEnabled:false,payoutEnabled:false,financialExecution:false,verifiedFinancialExecution:false,transactionsBuilt:0,broadcastTransactions:0};
}
function finish(r){
 const tasks=new Set(["independently_verify_core_network_and_sync"]);
 if(r.result==="blocked")tasks.add("reobserve_public_rpc");
 for(const i of r.entries){
  r.summary.counts[i.reviewState]=(r.summary.counts[i.reviewState]??0)+1;
  if(i.reviewState==="archive_candidate_pending_independent_core_trust")tasks.add("review_archived_entries");
  if(i.reviewState==="investigate_missing")tasks.add("investigate_not_found");
  if(["conflicting_evidence","insufficient_evidence"].includes(i.reviewState))tasks.add("reobserve_public_rpc");
  if([i.publicTtl,i.coreTtl].some(t=>t&&t.ttlRemainingLedgers<=REVIEW_TTL_LEDGERS))tasks.add("review_low_ttl");
 }
 r.summary.reviewTasks=[...tasks].sort();return r;
}
const evidence=i=>Object.fromEntries(["status","reason","observedLedger","observedWasmHash","computedWasmSha256","wasmSize","ledgerKeySha256","identityVerified","sha256Verified","lastModifiedLedgerSeq"].filter(k=>own(i,k)).map(k=>[k,i[k]]));
const ttl=i=>({observedLedger:i.observedLedger,liveUntilLedgerSeq:i.liveUntilLedgerSeq,ttlRemainingLedgers:i.ttlRemainingLedgers});
export function reconcileEvidence(audit,core){
 const r=emptyReport();let auditOk=false,coreOk=false;
 try{validateAuditPins();}catch{r.errors.push("manifest_or_dependency_pin_invalid");return finish(r);}
 const targets=targetsFor(TESTNET);
 try{auditValid(audit,targets);auditOk=true;}catch{r.errors.push("invalid_audit_evidence");}
 try{coreValid(core,targets);coreOk=true;}catch{r.errors.push("invalid_core_evidence");}
 if(!auditOk||!coreOk)return finish(r);
 r.observedLedgers={audit:audit.observedLedger,auditSpan:{first:audit.ledgerSpan.first,last:audit.ledgerSpan.last},core:core.ledger,corePublicRpcBracket:{first:core.publicRpcBracket.first,last:core.publicRpcBracket.last}};
 if(audit.entries.some(i=>Math.abs(i.observedLedger-core.ledger)>MAX_SNAPSHOT_GAP)||distance(core.ledger,audit.ledgerSpan)>MAX_SNAPSHOT_GAP||
    Math.max(Math.abs(core.publicRpcBracket.first-audit.ledgerSpan.first),Math.abs(core.publicRpcBracket.last-audit.ledgerSpan.last))>MAX_SNAPSHOT_GAP){r.errors.push("stale_snapshot_evidence");return finish(r);}
 r.result="review_required";
 r.entries.forEach((i,n)=>{
  const a=audit.entries[n],c=core.entries[n];
  i.publicEvidence=evidence(a);i.coreEvidence=evidence(c);
  const publicLive=["healthy","low_ttl"].includes(a.status);
  i.publicTtl=publicLive?ttl(a):null;i.coreTtl=c.status==="live"?ttl(c):null;
  if([a.status,c.status].some(s=>s==="indeterminate"))i.reviewState="insufficient_evidence";
  else if(a.status==="unavailable_live_entry"&&c.status==="archived"&&(a.liveUntilLedgerSeq===null||a.liveUntilLedgerSeq<c.observedLedger))i.reviewState="archive_candidate_pending_independent_core_trust";
  else if(a.status==="unavailable_live_entry"&&c.status==="not_found")i.reviewState="investigate_missing";
  else if(publicLive&&c.status==="live"&&a.liveUntilLedgerSeq===c.liveUntilLedgerSeq)i.reviewState=a.status==="low_ttl"||c.ttlRemainingLedgers<=REVIEW_TTL_LEDGERS?"live_ttl_review":"live_lifecycle_review";
  else i.reviewState="conflicting_evidence";
 });
 if(r.entries.some(i=>["insufficient_evidence","conflicting_evidence"].includes(i.reviewState))){r.result="blocked";r.errors.push("incomplete_or_conflicting_entry_evidence");}
 return finish(r);
}
export function runCli(args){
 try{
  const {auditPath,corePath}=parseArguments(args);
  let a,c;const errors=[];
  try{a=readEvidenceFile(auditPath);}catch{errors.push("audit_file_unreadable_or_invalid");}
  try{c=readEvidenceFile(corePath);}catch{errors.push("core_file_unreadable_or_invalid");}
  if(errors.length){const r=emptyReport();r.errors=errors;return finish(r);}
  return reconcileEvidence(a,c);
 }catch{const r=emptyReport();r.errors=["invalid_arguments_or_review_failed"];return finish(r);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 console.log(JSON.stringify(runCli(process.argv.slice(2)),null,2));process.exitCode=1;
}
