import {readFileSync} from "node:fs";
import {pathToFileURL} from "node:url";
import {rpc} from "@stellar/stellar-sdk";
import {TESTNET} from "./manifest.mjs";
import {validateManifest} from "./preflight.mjs";
import {validateDependencyPins,targetsFor,publicTarget,observeEntry,observationConsistent,summarize,REVIEW_TTL_LEDGERS,STRICT_MARGIN_LEDGERS,MAX_LEDGER_SPAN} from "./audit-helpers.mjs";

export function validateAuditPins(manifest=TESTNET){
 validateManifest(manifest);
 if(manifest.referenceCommit!==TESTNET.referenceCommit||Object.entries(TESTNET.contracts).some(([name,pin])=>manifest.contracts[name].id!==pin.id||manifest.contracts[name].hash!==pin.hash))throw Error("Manifest release pin mismatch");
 const pkg=path=>JSON.parse(readFileSync(new URL(path,import.meta.url),"utf8"));
 const declared=pkg("../package.json");
 validateDependencyPins(declared.dependencies,Object.fromEntries(
  ["smart-account-kit","@stellar/stellar-sdk"].map(name=>[name,pkg(`../node_modules/${name}/package.json`).version])
 ));
}
// Deliberately only these three public observation methods are used. No transaction API.
export async function collectEntries(server,targets){
 return Promise.all(targets.map(async target=>{
  try{return observeEntry(target,await server.getLedgerEntries(target.key));}
  catch{return {...publicTarget(target),reason:"rpc_observation_failed"};}
 }));
}
function emptyReport(){
 return {schema_version:1,network:{name:"Stellar Testnet",rpcUrl:TESTNET.rpcUrl,expectedPassphrase:TESTNET.networkPassphrase,verified:false},
  observedLedger:null,ledgerSpan:null,observationVerified:false,
  policy:{reviewTtlLedgers:REVIEW_TTL_LEDGERS,strictVerifierMarginLedgers:STRICT_MARGIN_LEDGERS,maxLedgerSpan:MAX_LEDGER_SPAN,maxLedgerAgeSeconds:120},
  entries:targetsFor(TESTNET).map(publicTarget),errors:[],
  canDeployCustomerWallet:false,customerWalletCreated:false,credentialRecoveryVerified:false,verifiedFinancialExecution:false,broadcastTransactions:0,transactionsBuilt:0};
}
export async function auditLive({manifest=TESTNET,server,now=Date.now}={}){
 const report=emptyReport();
 try{validateAuditPins(manifest);}catch{report.errors.push("manifest_or_dependency_pin_invalid");return finish(report);}
 server??=new rpc.Server(TESTNET.rpcUrl,{timeout:15});
 let network;
 try{network=await server.getNetwork();}catch{report.errors.push("network_observation_failed");return finish(report);}
 if(network?.passphrase!==TESTNET.networkPassphrase){report.errors.push("wrong_network");return finish(report);}
 report.network.verified=true;
 let start,end;
 try{start=await server.getLatestLedger();}catch{report.errors.push("start_ledger_observation_failed");}
 report.entries=await collectEntries(server,targetsFor(manifest));
 try{end=await server.getLatestLedger();}catch{report.errors.push("end_ledger_observation_failed");}
 report.observationVerified=observationConsistent(start,end,report.entries,now());
 if(report.observationVerified){
  report.observedLedger=end.sequence;
  report.ledgerSpan={first:start.sequence,last:end.sequence};
 }else{
  report.errors.push("stale_noncanonical_or_inconsistent_ledger_span");
  report.entries=report.entries.map(item=>({...item,status:item.status==="mismatch"?"mismatch":"indeterminate",reason:item.status==="mismatch"?item.reason:"unverified_ledger_context"}));
 }
 return finish(report);
}
function finish(report){
 report.summary=summarize(report.entries,report.network.verified&&report.observationVerified);
 if(report.errors.length&&!report.summary.actions.includes("retry_observation"))report.summary.actions.push("retry_observation");
 report.summary.actions.sort();
 return report;
}
export const auditExitCode=report=>report.summary.verified?0:1;
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 auditLive().then(report=>{console.log(JSON.stringify(report,null,2));process.exitCode=auditExitCode(report);}).catch(()=>{
  // Never print exception text: injected RPC errors may contain request/response data.
  const report=emptyReport();
  report.errors.push("audit_failed");
  console.log(JSON.stringify(finish(report),null,2));process.exitCode=1;
 });
}
