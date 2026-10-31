import {createHash} from "node:crypto";
import {pathToFileURL} from "node:url";
import {rpc,StrKey,xdr} from "@stellar/stellar-sdk";
import {KNOWN_AUTH_DIGEST_SCHEMES} from "smart-account-kit";
import {TESTNET} from "./manifest.mjs";
const hex64=value=>typeof value==="string"&&/^[0-9a-f]{64}$/.test(value);
export function validateManifest(manifest=TESTNET){
 if(manifest.networkPassphrase!=="Test SDF Network ; September 2015")
  throw Error("Refusing non-Testnet passphrase");
 if(manifest.rpcUrl!=="https://soroban-testnet.stellar.org")
  throw Error("RPC must be pinned to official Stellar Testnet");
 if(manifest.kitVersion!=="0.10.0")throw Error("Smart Account Kit version mismatch");
 if(!hex64(manifest.accountWasmHash)||manifest.accountWasmSize!==48273)
  throw Error("Smart account artifact not pinned");
 if(manifest.authDigestScheme!=="preimage-v1"||
  KNOWN_AUTH_DIGEST_SCHEMES[manifest.accountWasmHash]!=="preimage-v1")
  throw Error("Kit authorization digest scheme does not match account artifact");
 if(!manifest.contracts||Object.keys(manifest.contracts).sort().join(",")!==
   ["spendingLimit","threshold","webauthn"].sort().join(","))
  throw Error("Incomplete verifier/policy release manifest");
 for(const item of Object.values(manifest.contracts)){
  if(!StrKey.isValidContract(item.id)||!hex64(item.hash))
   throw Error("Invalid contract identity");
 }
 return true;
}
function ttlCurrent(entry,latestLedger,buffer=720){
 return Number.isSafeInteger(entry?.liveUntilLedgerSeq)&&
  entry.liveUntilLedgerSeq>latestLedger+buffer;
}
export function validateCodeEntry(entry,expectedHash,expectedSize,latestLedger){
 if(!entry||!ttlCurrent(entry,latestLedger)||entry.val?.switch?.().name!=="contractCode")
  throw Error("Account WASM missing or near expiry");
 const code=entry.val.contractCode();
 const bytes=code.code();
 if(bytes.length!==expectedSize||code.hash().toString("hex")!==expectedHash||
    createHash("sha256").update(bytes).digest("hex")!==expectedHash)
  throw Error("On-chain account WASM differs from pinned bytes");
 return {size:bytes.length,ttlRemainingLedgers:entry.liveUntilLedgerSeq-latestLedger};
}
export function validateContractEntry(entry,expectedHash,latestLedger){
 if(!entry||!ttlCurrent(entry,latestLedger)||entry.val?.switch?.().name!=="contractData")
  throw Error("Verifier/policy instance absent or near TTL expiry");
 const val=entry.val.contractData().val();
 if(val.switch().name!=="scvContractInstance")throw Error("No contract instance");
 const executable=val.instance().executable();
 if(executable.switch().name!=="contractExecutableWasm"||
    executable.wasmHash().toString("hex")!==expectedHash)
  throw Error("Verifier/policy WASM hash differs from pinned release");
 return {ttlRemainingLedgers:entry.liveUntilLedgerSeq-latestLedger};
}
export async function verifyLive(manifest=TESTNET,server=new rpc.Server(manifest.rpcUrl)){
 validateManifest(manifest);
 const network=await server.getNetwork();
 if(network.passphrase!==manifest.networkPassphrase)
  throw Error("RPC network is not Stellar Testnet");
 const key=xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({
  hash:Buffer.from(manifest.accountWasmHash,"hex")}));
 const codeResult=await server.getLedgerEntries(key);
 if(!Number.isSafeInteger(codeResult.latestLedger)||codeResult.latestLedger<=0)
  throw Error("Invalid network ledger observation");
 const account=validateCodeEntry(codeResult.entries?.[0],manifest.accountWasmHash,
  manifest.accountWasmSize,codeResult.latestLedger);
 const checks={};
 for(const [name,{id,hash}] of Object.entries(manifest.contracts)){
  const contractKey=xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
   contract:xdr.ScAddress.scAddressTypeContract(StrKey.decodeContract(id)),
   key:xdr.ScVal.scvLedgerKeyContractInstance(),
   durability:xdr.ContractDataDurability.persistent()
  }));
  const record=await server.getLedgerEntries(contractKey);
  if(Math.abs(record.latestLedger-codeResult.latestLedger)>12)
   throw Error("RPC observations are too far apart");
  checks[name]=validateContractEntry(record.entries?.[0],hash,record.latestLedger);
 }
 return {
  result:"read-only-code-preflight-passed",
  network:"Stellar Testnet",
  accountWasmHash:manifest.accountWasmHash,
  authDigestScheme:manifest.authDigestScheme,
  latestLedger:codeResult.latestLedger,
  account,contracts:checks,
  ttlExtensionReviewRequired:
   [account,...Object.values(checks)].some(item=>item.ttlRemainingLedgers<7*17280),
  canDeployCustomerWallet:false,
  credentialRecoveryVerified:false,
  verifiedFinancialExecution:false,
  broadcastTransactions:0
 };
}
async function main(){
 const result=await verifyLive();
 console.log(JSON.stringify(result,null,2));
 console.log("This is NOT a wallet deployment or permission to accept funds.");
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(error=>{console.error("READ-ONLY PREFLIGHT FAILED:",error.message);process.exitCode=1;});
}
