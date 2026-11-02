import {createHash} from "node:crypto";
import {StrKey,xdr} from "@stellar/stellar-sdk";

export const REVIEW_TTL_LEDGERS=7*17280;
export const STRICT_MARGIN_LEDGERS=720;
export const MAX_LEDGER_SPAN=12;
export const isLedger=n=>Number.isInteger(n)&&n>0&&n<=0xffffffff;
const digest=bytes=>createHash("sha256").update(bytes).digest("hex");
const codeKey=hash=>xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({hash:Buffer.from(hash,"hex")}));
export function targetsFor(manifest){
 const targets=[{name:"account_code",kind:"code",hash:manifest.accountWasmHash,size:manifest.accountWasmSize,key:codeKey(manifest.accountWasmHash)}];
 for(const [name,{id,hash}] of Object.entries(manifest.contracts)){
  targets.push({name:`${name}_instance`,kind:"instance",id,hash,key:xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
   contract:xdr.ScAddress.scAddressTypeContract(StrKey.decodeContract(id)),key:xdr.ScVal.scvLedgerKeyContractInstance(),durability:xdr.ContractDataDurability.persistent()
  }))});
  targets.push({name:`${name}_code`,kind:"code",hash,key:codeKey(hash)});
 }
 return targets;
}
export function publicTarget(target){
 return {name:target.name,kind:target.kind,...(target.id?{contractId:target.id}:{}),expectedWasmHash:target.hash,observedLedger:null,liveUntilLedgerSeq:null,ttlRemainingLedgers:null,status:"indeterminate",reason:"not_observed"};
}
export function observeEntry(target,result){
 const item=publicTarget(target);
 if(!isLedger(result?.latestLedger))return {...item,reason:"noncanonical_ledger"};
 item.observedLedger=result.latestLedger;
 if(!Array.isArray(result.entries)||result.entries.length>1)return {...item,reason:"malformed_entries"};
 if(result.entries.length===0)return {...item,status:"unavailable_live_entry",reason:"live_only_absence_archive_or_nonexistent_ambiguous"};
 const entry=result.entries[0];
 // Preserve valid raw expiration even when identity verification fails.
 if(Number.isInteger(entry?.liveUntilLedgerSeq)&&entry.liveUntilLedgerSeq>0&&entry.liveUntilLedgerSeq<=0xffffffff){
  item.liveUntilLedgerSeq=entry.liveUntilLedgerSeq;
  if(entry.liveUntilLedgerSeq>=result.latestLedger)item.ttlRemainingLedgers=entry.liveUntilLedgerSeq-result.latestLedger;
 }
 try{
  if(entry.key.toXDR("base64")!==target.key.toXDR("base64"))return {...item,status:"mismatch",reason:"returned_key_mismatch"};
  if(entry.lastModifiedLedgerSeq!==undefined&&(!isLedger(entry.lastModifiedLedgerSeq)||entry.lastModifiedLedgerSeq>result.latestLedger))return {...item,reason:"invalid_last_modified_ledger"};
  if(target.kind==="code"){
   if(entry.val.switch().name!=="contractCode")return {...item,status:"mismatch",reason:"entry_type_mismatch"};
   const code=entry.val.contractCode();
   item.observedWasmHash=code.hash().toString("hex");
   item.computedWasmSha256=digest(code.code());
   item.wasmSize=code.code().length;
   if(item.observedWasmHash!==target.hash||item.computedWasmSha256!==target.hash||(target.size!==undefined&&item.wasmSize!==target.size))return {...item,status:"mismatch",reason:"wasm_identity_mismatch"};
  }else{
   if(entry.val.switch().name!=="contractData")return {...item,status:"mismatch",reason:"entry_type_mismatch"};
   const data=entry.val.contractData();
   if(data.contract().toXDR("base64")!==target.key.contractData().contract().toXDR("base64")||data.key().switch().name!=="scvLedgerKeyContractInstance"||data.durability().name!=="persistent")return {...item,status:"mismatch",reason:"instance_identity_mismatch"};
   const val=data.val();
   if(val.switch().name!=="scvContractInstance"||val.instance().executable().switch().name!=="contractExecutableWasm")return {...item,status:"mismatch",reason:"instance_executable_mismatch"};
   item.observedWasmHash=val.instance().executable().wasmHash().toString("hex");
   if(item.observedWasmHash!==target.hash)return {...item,status:"mismatch",reason:"instance_wasm_hash_mismatch"};
  }
  // Some RPCs return archived code/instance XDR with a zero liveUntilLedgerSeq
  // sentinel. A matching code hash does NOT establish a live usable entry.
  // Treat this as requiring a separate archival/nonexistence investigation,
  // never as a current expiration of ledger 0 or as verified customer custody.
  if(entry.liveUntilLedgerSeq===0)return {...item,status:"unavailable_live_entry",
   reason:"rpc_zero_ttl_no_verified_live_entry",liveUntilLedgerSeq:null,ttlRemainingLedgers:null};
  if(!isLedger(entry.liveUntilLedgerSeq))return {...item,reason:"ttl_unavailable_or_noncanonical"};
  item.liveUntilLedgerSeq=entry.liveUntilLedgerSeq;
  if(entry.liveUntilLedgerSeq<result.latestLedger)return {...item,status:"unavailable_live_entry",
   reason:"reported_ttl_precedes_observation_live_state_unconfirmed",ttlRemainingLedgers:null};
  item.ttlRemainingLedgers=entry.liveUntilLedgerSeq-result.latestLedger;
  return {...item,status:item.ttlRemainingLedgers<=REVIEW_TTL_LEDGERS?"low_ttl":"healthy",reason:"identity_and_live_ttl_observed"};
 }catch{return {...item,status:"indeterminate",reason:"malformed_xdr_entry"};}
}
// Validate the RPC's ledger header, not a coerced/string sequence or an arbitrary hash.
export function anchorValid(anchor,nowMs){
 try{
  if(!isLedger(anchor?.sequence)||! /^[0-9a-f]{64}$/.test(anchor.id)||! /^(0|[1-9][0-9]*)$/.test(anchor.closeTime))return false;
  const close=Number(anchor.closeTime);
  return Number.isSafeInteger(close)&&close*1000<=nowMs+30000&&nowMs-close*1000<=120000&&
   anchor.headerXdr.ledgerSeq()===anchor.sequence&&anchor.headerXdr.scpValue().closeTime().toString()===anchor.closeTime&&digest(anchor.headerXdr.toXDR())===anchor.id;
 }catch{return false;}
}
export function observationConsistent(start,end,items,nowMs){
 return anchorValid(start,nowMs)&&anchorValid(end,nowMs)&&end.sequence>=start.sequence&&end.sequence-start.sequence<=MAX_LEDGER_SPAN&&
  (start.sequence!==end.sequence||start.id===end.id)&&items.every(item=>item.observedLedger===null||
   (isLedger(item.observedLedger)&&item.observedLedger>=start.sequence&&item.observedLedger<=end.sequence));
}
export function summarize(items,verifiedContext){
 const actions={low_ttl:"review_extension",unavailable_live_entry:"investigate_restore_or_republish",mismatch:"investigate_mismatch",indeterminate:"retry_observation"};
 const ttls=items.map(item=>item.ttlRemainingLedgers).filter(Number.isInteger);
 return {verified:verifiedContext&&items.every(item=>item.status==="healthy"),minimumTtlRemainingLedgers:verifiedContext&&ttls.length?Math.min(...ttls):null,
  minimumTtlScope:"observed_entries_with_valid_ttl_only",
  actions:[...new Set(items.map(item=>actions[item.status]).filter(Boolean))].sort()};
}

export function validateDependencyPins(declared,installed){
 for(const [name,version] of [["smart-account-kit","0.10.0"],["@stellar/stellar-sdk","16.4.1"]]){
  if(declared?.[name]!==version||installed?.[name]!==version)throw Error("Dependency version pin mismatch");
 }
 return true;
}
