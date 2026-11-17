// Test-only tripwire. Also usable as `node --import ./test-support/offline-guard.mjs ...`.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import cp from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
export function installOfflineGuard(){
 const undo=[];
 const replace=(obj,key,value)=>{const previous=obj[key];undo.push(()=>{obj[key]=previous;});obj[key]=value;};
 const deny=()=>{throw Error('forbidden_offline_side_effect');};
 replace(globalThis,'fetch',deny);
 for(const [mod,keys] of [[http,['request','get']],[https,['request','get']],[net,['connect','createConnection']],[tls,['connect']],[dns,['lookup','resolve']],[cp,['spawn','exec','execFile','fork','spawnSync','execSync','execFileSync']],[fs,['writeFileSync','appendFileSync','mkdirSync','unlinkSync','renameSync','rmSync','truncateSync','createWriteStream','writeFile','appendFile','mkdir','unlink','rename','rm','truncate']]])for(const key of keys)replace(mod,key,deny);
 const readOnly=flags=>flags==='r'||(typeof flags==='number'&&(flags&(fs.constants.O_WRONLY|fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_TRUNC|fs.constants.O_APPEND))===0);
 const open=fs.openSync;replace(fs,'openSync',(p,flags,...args)=>{if(!readOnly(flags))deny();return open(p,flags,...args);});
 const asyncOpen=fs.promises.open;replace(fs.promises,'open',(p,flags,...args)=>{if(!readOnly(flags))deny();return asyncOpen(p,flags,...args);});
 const write=fs.writeSync;replace(fs,'writeSync',(fd,...args)=>{if(fd!==1&&fd!==2)deny();return write(fd,...args);});
 for(const key of ['writeFile','appendFile','mkdir','unlink','rename','rm','truncate'])replace(fs.promises,key,deny);
 syncBuiltinESMExports();
 return ()=>{for(const restore of undo.reverse())restore();syncBuiltinESMExports();};
}
// Preloading this fixture arms the guard before the CLI or its dependencies load.
if(process.argv.includes('--import')||process.execArgv.some(arg=>arg.includes('offline-guard.mjs')))installOfflineGuard();
