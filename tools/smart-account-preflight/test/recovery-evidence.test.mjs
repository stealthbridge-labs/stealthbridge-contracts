import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync,rmSync,symlinkSync,chmodSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {installOfflineGuard} from '../test-support/offline-guard.mjs';
import {reconcileEvidence,runCli,readEvidenceFile,parseArguments,MAX_FILE_BYTES} from '../src/recovery-evidence.mjs';
import {summarize,REVIEW_TTL_LEDGERS} from '../src/audit-helpers.mjs';
import {finishReview} from '../src/core-archival-review.mjs';
const fixture=name=>JSON.parse(readFileSync(new URL(`fixtures/${name}.json`,import.meta.url),'utf8'));
const pair=()=>[fixture('public-audit'),fixture('core-review')];
function refresh(a,c){a.summary=summarize(a.entries,true);finishReview(c);}
function blocked(r){assert.equal(r.result,'blocked');assert.ok(r.errors.length);assert.equal(r.canDeployCustomerWallet,false);assert.equal(r.transactionsBuilt,0);}
function temporary(fn){const dir=mkdtempSync(join(tmpdir(),'recovery-evidence-'));try{return fn(dir);}finally{rmSync(dir,{recursive:true,force:true});}}

test('realistic seven-entry report JSON reconciles five archive candidates and two live observations',()=>{
 const [a,c]=pair(),before=JSON.stringify([a,c]),r=reconcileEvidence(a,c);
 assert.equal(r.result,'review_required');assert.equal(r.entries.length,7);
 assert.equal(r.summary.counts.archive_candidate_pending_independent_core_trust,5);
 assert.equal(r.summary.counts.live_lifecycle_review,2);
 assert.equal(r.source.type,'operator_owned');assert.equal(r.source.coreNetworkVerified,false);
 assert.equal(r.policy.inputAuthenticityEstablished,false);assert.equal(r.policy.currentFreshnessEstablished,false);
 assert.equal(JSON.stringify([a,c]),before);assert.deepEqual(r,reconcileEvidence(a,c));
 for(const key of ['independentCoreTrustEstablished','canDeployCustomerWallet','customerWalletReady','customerWalletCreated','credentialRecoveryVerified','vaultEnabled','privacyEnabled','payoutEnabled','financialExecution','verifiedFinancialExecution'])assert.equal(r[key],false);
});
const mutations=[
 ['missing Core evidence',(a,c)=>[a,null]],
 ['missing audit evidence',(a,c)=>[null,c]],
 ['missing entries',(a,c)=>{a.entries.pop();}],
 ['extra entries',(a,c)=>{c.entries.push(c.entries[0]);}],
 ['duplicate entries',(a,c)=>{a.entries[1]=structuredClone(a.entries[0]);}],
 ['reordered entries',(a,c)=>{c.entries.reverse();}],
 ['malformed entry',(a,c)=>{a.entries[0]=null;}],
 ['wrong contract ID',(a,c)=>{a.entries[1].contractId=c.entries[3].contractId;}],
 ['wrong expected code hash',(a,c)=>{a.entries[0].expectedWasmHash='00'.repeat(32);}],
 ['wrong observed hash',(a,c)=>{c.entries[0].observedWasmHash='00'.repeat(32);}],
 ['wrong computed hash',(a,c)=>{c.entries[0].computedWasmSha256='00'.repeat(32);}],
 ['missing observed hash',(a,c)=>{delete c.entries[1].observedWasmHash;}],
 ['missing code size',(a,c)=>{delete c.entries[0].wasmSize;}],
 ['wrong account size',(a,c)=>{c.entries[0].wasmSize++;}],
 ['forged ledger key digest',(a,c)=>{c.entries[0].ledgerKeySha256='00'.repeat(32);}],
 ['unverified identity',(a,c)=>{c.entries[0].identityVerified=false;}],
 ['unverified code SHA',(a,c)=>{c.entries[0].sha256Verified=false;}],
 ['instance claims code SHA',(a,c)=>{c.entries[1].sha256Verified=true;}],
 ['future last modification',(a,c)=>{c.entries[0].lastModifiedLedgerSeq=c.ledger+1;}],
 ['missing last modification',(a,c)=>{delete c.entries[0].lastModifiedLedgerSeq;}],
 ['fabricated remaining TTL',(a,c)=>{a.entries[1].ttlRemainingLedgers++;}],
 ['invented archived TTL',(a,c)=>{c.entries[0].liveUntilLedgerSeq=c.ledger+100;}],
 ['historical TTL relabeled live',(a,c)=>{a.entries[0].status='healthy';a.entries[0].liveUntilLedgerSeq=a.observedLedger-1;a.entries[0].ttlRemainingLedgers=200000;}],
 ['zero TTL as expiration',(a,c)=>{a.entries[0].liveUntilLedgerSeq=0;}],
 ['forged healthy status with low TTL',(a,c)=>{a.entries[1].liveUntilLedgerSeq=a.observedLedger+1;a.entries[1].ttlRemainingLedgers=1;}],
 ['string ledger',(a,c)=>{c.ledger=String(c.ledger);}],
 ['entry outside audit bracket',(a,c)=>{a.entries[0].observedLedger++;}],
 ['entry outside Core snapshot',(a,c)=>{c.entries[0].observedLedger++;}],
 ['audit end ledger mismatch',(a,c)=>{a.observedLedger--;}],
 ['wide bracket',(a,c)=>{c.publicRpcBracket.last+=13;}],
 ['forged source',(a,c)=>{c.source.type='independent_consensus';}],
 ['forged Core network trust',(a,c)=>{c.source.coreNetworkVerified=true;}],
 ['forged source warning',(a,c)=>{c.source.trustWarning='Authenticated consensus proof';}],
 ['wrong audit network',(a,c)=>{a.network.expectedPassphrase='Public Global Stellar Network ; September 2015';}],
 ['wrong Core network',(a,c)=>{c.network.passphrase='other';}],
 ['forged public RPC URL',(a,c)=>{a.network.rpcUrl='https://attacker.invalid';}],
 ['unverified observation',(a,c)=>{c.observationVerified=false;}],
 ['forged policy',(a,c)=>{a.policy.reviewTtlLedgers=0;}],
 ['unexpected execution claim',(a,c)=>{a.vaultEnabled=true;}],
 ['permission payload',(a,c)=>{c.authorization={createAccount:true,privacy:true,payout:true};}],
 ['missing mandatory disabled flag',(a,c)=>{delete a.canDeployCustomerWallet;}],
 ['execution enabled',(a,c)=>{c.verifiedFinancialExecution=true;}],
 ['claimed transaction built',(a,c)=>{a.transactionsBuilt=1;}],
 ['input errors',(a,c)=>{c.errors=['observation_failed'];}],
 ['unknown entry field',(a,c)=>{c.entries[0].authorization=true;}],
];
for(const [name,mutate] of mutations)test(`fail closed: ${name}`,()=>{let [a,c]=pair();const replacement=mutate(a,c);if(replacement)[a,c]=replacement;if(a&&c){try{refresh(a,c);}catch{ /* malformed entry is rejected before summary use */ }}blocked(reconcileEvidence(a,c));});

test('summary flags and minima are checked against entries, never accepted as authority',()=>{
 for(const side of [0,1])for(const key of [side?'allEntriesLive':'verified',side?'minimumLiveTtlRemainingLedgers':'minimumTtlRemainingLedgers']){
  const p=pair();p[side].summary[key]=key.includes('minimum')?999999:true;blocked(reconcileEvidence(...p));
 }
});
test('aligned low TTL remains review only at the exact threshold',()=>{
 const [a,c]=pair();for(const i of [a.entries[1],c.entries[1]]){i.liveUntilLedgerSeq=i.observedLedger+REVIEW_TTL_LEDGERS;i.ttlRemainingLedgers=REVIEW_TTL_LEDGERS;}a.entries[1].status='low_ttl';refresh(a,c);
 const r=reconcileEvidence(a,c);assert.equal(r.result,'review_required');assert.equal(r.entries[1].reviewState,'live_ttl_review');assert.ok(r.summary.reviewTasks.includes('review_low_ttl'));
});
test('Core not found is investigation, never evidence of archival',()=>{
 const [a,c]=pair(),i=c.entries[0];i.status='not_found';i.reason='core_reports_not_found';i.identityVerified=false;i.sha256Verified=false;
 for(const k of ['observedWasmHash','computedWasmSha256','wasmSize','lastModifiedLedgerSeq'])delete i[k];refresh(a,c);
 const r=reconcileEvidence(a,c);assert.equal(r.entries[0].reviewState,'investigate_missing');assert.equal(r.summary.counts.archive_candidate_pending_independent_core_trust,4);
 i.identityVerified=true;refresh(a,c);blocked(reconcileEvidence(a,c));
});
test('matching identities cannot reconcile live versus archived or contradictory expirations',()=>{
 for(const state of ['archived','live']){const [a,c]=pair();if(state==='archived'){c.entries[1].status=state;c.entries[1].reason='core_reports_archived_identity_verified';c.entries[1].liveUntilLedgerSeq=null;c.entries[1].ttlRemainingLedgers=null;}else{c.entries[1].liveUntilLedgerSeq++;c.entries[1].ttlRemainingLedgers++;}refresh(a,c);blocked(reconcileEvidence(a,c));}
});
test('indeterminate or mismatch cannot be upgraded by summary flags',()=>{
 for(const status of ['indeterminate','mismatch']){const [a,c]=pair();a.entries[0].status=status;refresh(a,c);blocked(reconcileEvidence(a,c));}
});
function shiftCore(c,n){c.ledger+=n;c.publicRpcBracket.first+=n;c.publicRpcBracket.last+=n;for(const i of c.entries){i.observedLedger+=n;if(i.status==='live')i.ttlRemainingLedgers-=n;}}
test('stale prior snapshot and separated RPC brackets fail despite internally consistent entries',()=>{
 for(const delta of [-25,25]){const [a,c]=pair();shiftCore(c,delta);refresh(a,c);blocked(reconcileEvidence(a,c));}
 const [a,c]=pair();shiftCore(c,24);c.publicRpcBracket.first+=12;c.publicRpcBracket.last+=12;refresh(a,c);blocked(reconcileEvidence(a,c));
});
test('24-ledger alignment boundary accepted as historical review only',()=>{
 const [a,c]=pair();shiftCore(c,24);refresh(a,c);const r=reconcileEvidence(a,c);assert.equal(r.result,'review_required');assert.equal(r.policy.currentFreshnessEstablished,false);
});
test('no prior successful report is cached after missing evidence',()=>{const p=pair();assert.equal(reconcileEvidence(...p).result,'review_required');blocked(reconcileEvidence(p[0],undefined));});
test('strict CLI argument contract rejects missing, duplicate and extra flags',()=>{
 assert.deepEqual(parseArguments(['--core-json','c','--audit-json','a']),{auditPath:'a',corePath:'c'});
 for(const args of [[],['--audit-json','a'],['--audit-json','a','--audit-json','c'],['--audit-json','a','--core-json',''],['--audit-json','a','--core-json','c','--execute'],['--core-url','http://localhost','--audit-json','a']]){assert.throws(()=>parseArguments(args));blocked(runCli(args));}
});
test('input leaf symlinks, missing, unreadable, directories and oversized files fail closed',()=>temporary(dir=>{
 const good=join(dir,'good.json');writeFileSync(good,'{}');const link=join(dir,'link');symlinkSync(good,link);
 const huge=join(dir,'huge');writeFileSync(huge,' '.repeat(MAX_FILE_BYTES+1));const denied=join(dir,'denied');writeFileSync(denied,'{}');chmodSync(denied,0);
 for(const path of [link,join(dir,'missing'),denied,dir,huge]){assert.throws(()=>readEvidenceFile(path));blocked(runCli(['--audit-json',path,'--core-json',good]));}
}));
test('malformed JSON, invalid UTF8 and exact byte limit are bounded',()=>temporary(dir=>{
 const file=join(dir,'input');for(const data of ['{',Buffer.from([0xff]),'null']){writeFileSync(file,data);blocked(runCli(['--audit-json',file,'--core-json',file]));}
 writeFileSync(file,'{}'+' '.repeat(MAX_FILE_BYTES-2));assert.deepEqual(readEvidenceFile(file),{});
}));
test('CLI handler performs no networking, subprocesses or file writes',()=>temporary(dir=>{
 const [a,c]=pair();const ap=join(dir,'audit.json'),cp=join(dir,'core.json');
 writeFileSync(ap,JSON.stringify(a));writeFileSync(cp,JSON.stringify(c));
 const before=readdirSync(dir).sort(),restore=installOfflineGuard();
 try{
  const r=runCli(['--audit-json',ap,'--core-json',cp]);assert.equal(r.result,'review_required');assert.equal(r.source.type,'operator_owned');assert.equal(r.broadcastTransactions,0);
  const bad=runCli(['--audit-json',join(dir,'PRIVATE-missing'),'--core-json',cp]);blocked(bad);assert.doesNotMatch(JSON.stringify(bad),/PRIVATE/);
 }finally{restore();}
 assert.deepEqual(readdirSync(dir).sort(),before);assert.equal(readFileSync(ap,'utf8'),JSON.stringify(a));assert.equal(readFileSync(cp,'utf8'),JSON.stringify(c));
}));
