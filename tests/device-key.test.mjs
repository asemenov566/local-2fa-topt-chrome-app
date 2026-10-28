import test from 'node:test';
import assert from 'node:assert/strict';
import {createKey,seal,exportKey} from '../extension/vault.js';
import {rememberKey,recallKey,prepareRememberKey,changeSessionLifetime} from '../extension/security.js';
import {sessionAlive,sessionLifetime,reconcileSessionPolicy} from '../extension/session.js';

let local,session,wrapped,queue=Promise.resolve(),failNative=false,calls,interceptNative;
function storage(which) {return {
 async get(keys){const data=which();return structuredClone(keys==null?data:Object.fromEntries((Array.isArray(keys)?keys:[keys]).filter(k=>k in data).map(k=>[k,data[k]])));},
 async set(values){Object.assign(which(),structuredClone(values));},
 async remove(keys){for(const key of Array.isArray(keys)?keys:[keys])delete which()[key];}
};}
globalThis.chrome={storage:{local:storage(()=>local),session:storage(()=>session)},runtime:{connectNative(){
 let callback;return {onMessage:{addListener(fn){callback=fn;}},onDisconnect:{addListener(){}},disconnect(){},postMessage(request){calls.push(request.op);queueMicrotask(async()=>{
  if(interceptNative)await interceptNative(request);
  if(failNative){callback({ok:false,error:'Synthetic unavailable DPAPI'});return;}
  if(request.op==='protect-key'){const value=btoa(crypto.randomUUID());wrapped.set(value,request.key);callback({ok:true,wrapped:value});}
  else if(request.op==='unprotect-key'&&wrapped.has(request.wrapped))callback({ok:true,key:wrapped.get(request.wrapped)});
  else callback({ok:false,error:'Synthetic invalid wrapper'});
 });}};
}}};
Object.defineProperty(navigator,'locks',{configurable:true,value:{request(name,fn){const result=queue.then(fn);queue=result.catch(()=>{});return result;}}});
function reset(){local={protectedMode:false};session={};wrapped=new Map();calls=[];failNative=false;interceptNative=null;}

test('persistent convenience key is wrapped; restart and password change recover only the current vault',async()=>{
 reset();const first=await createKey('1234'),v=await seal([],first.key,first.salt,1,4);
 await rememberKey(first.key,first.salt,false);
 assert.equal(local.deviceKey.protection,'windows-dpapi');assert.equal(local.deviceKey.raw,undefined);
 assert.equal(JSON.stringify(local).includes(await exportKey(first.key)),false);
 session={};assert.equal((await recallKey(v,false)).salt,first.salt);
 const before=local.deviceKey.wrapped;
 const next=await createKey('abcdef'),v2=await seal([],next.key,next.salt,2,6);
 await rememberKey(next.key,next.salt,false);
 assert.notEqual(local.deviceKey.wrapped,before);assert.equal(local.deviceKey.salt,next.salt);
 session={};assert.equal((await recallKey(v2,false)).passwordLength,6);
 assert.equal(await recallKey(v,false),null);
});

test('raw legacy device keys are removed and never used to unlock',async()=>{
 reset();const created=await createKey('1234'),v=await seal([],created.key,created.salt,1,4);
 local.deviceKey={salt:created.salt,raw:await exportKey(created.key)};
 assert.equal(await recallKey(v,false),null);assert.equal(local.deviceKey,undefined);assert.deepEqual(calls,[]);
 local.deviceKey={salt:created.salt,raw:await exportKey(created.key)};session.manualLock=true;
 assert.equal(await recallKey(v,false),null);assert.equal(local.deviceKey,undefined);
});

test('security epoch, current protection setting and DPAPI errors fail closed',async()=>{
 reset();const created=await createKey('1234'),v=await seal([],created.key,created.salt,1,4);
 session={lockEpoch:2,manualLock:true};
 await assert.rejects(rememberKey(created.key,created.salt,false,1),/отменена/);assert.equal(local.deviceKey,undefined);assert.deepEqual(calls,[]);
 session={};local.protectedMode=true;await rememberKey(created.key,created.salt,false);
 assert.equal(local.deviceKey,undefined);assert.deepEqual(calls,[]);
 session={};local.protectedMode=false;failNative=true;
 await assert.rejects(rememberKey(created.key,created.salt,false));assert.equal(local.deviceKey,undefined);assert.equal(session.uiUnlock,undefined);
 failNative=false;await rememberKey(created.key,created.salt,false);session={};failNative=true;
 assert.equal(await recallKey(v,false),null);assert.equal(local.deviceKey,undefined);
});

function holdNative(op) {
 let release,started;
 const waiting=new Promise(resolve=>{release=resolve;}),entered=new Promise(resolve=>{started=resolve;});
 interceptNative=request=>{if(request.op===op){started();return waiting;}};
 return {release,entered};
}
async function lockPromptly() {
 const locked=navigator.locks.request('chrome-app-totp-security',()=>{session={manualLock:true,lockEpoch:(session.lockEpoch??0)+1};return true;});
 let timer;try {assert.equal(await Promise.race([locked,new Promise(resolve=>{timer=setTimeout(()=>resolve(false),500);})]),true,'Lock must complete while native response is still pending');}finally{clearTimeout(timer);}
}
test('delayed protect/unprotect never block manual lock and cannot restore the stale session',async()=>{
 reset();const created=await createKey('1234'),v=await seal([],created.key,created.salt,1,4);
 let held=holdNative('protect-key');
 const saving=rememberKey(created.key,created.salt,false).then(()=>false,e=>/отменена/.test(e.message));
 await held.entered;try{await lockPromptly();}finally{held.release();}
 assert.equal(await saving,true);assert.equal(session.uiUnlock,undefined);assert.equal(local.deviceKey,undefined);
 interceptNative=null;session={};await rememberKey(created.key,created.salt,false);session={};
 held=holdNative('unprotect-key');const opening=recallKey(v,false);
 await held.entered;try{await lockPromptly();}finally{held.release();}
 assert.equal(await opening,null);assert.equal(session.uiUnlock,undefined);
});

test('failed stale unwrap does not erase a newly stored wrapper; preflight avoids a second native operation',async()=>{
 reset();const created=await createKey('1234'),v=await seal([],created.key,created.salt,1,4);
 await rememberKey(created.key,created.salt,false);session={};
 const held=holdNative('unprotect-key'),opening=recallKey(v,false);await held.entered;
 await rememberKey(created.key,created.salt,false);const current=local.deviceKey.wrapped;
 failNative=true;held.release();assert.equal(await opening,null);assert.equal(local.deviceKey.wrapped,current);
 failNative=false;interceptNative=null;
 const token=await prepareRememberKey(created.key,created.salt,0),count=calls.length;
 failNative=true;await rememberKey(created.key,created.salt,false,0,token);
 assert.equal(calls.length,count,'Prepared commit must not invoke DPAPI again after the file write');
 await assert.rejects(rememberKey(created.key,created.salt,false,0,token),/отменена/);
});

test('session lifetime defaults to one minute, preserves deadline on save and rejects expired keys',async()=>{
 reset();local={protectedMode:true};const created=await createKey('1234'),v=await seal([],created.key,created.salt,1,4);
 assert.equal(sessionLifetime({}),60);assert.equal(sessionLifetime({sessionLifetime:30}),30);assert.equal(sessionLifetime({protectedMode:false}),0);
 await rememberKey(created.key,created.salt,true);const start=session.uiUnlock.authenticatedAt,deadline=session.uiUnlock.expiresAt;
 assert.equal(deadline-start,60000);assert.equal(sessionAlive(session.uiUnlock),true);
 await rememberKey(created.key,created.salt,true);assert.equal(session.uiUnlock.authenticatedAt,start);assert.equal(session.uiUnlock.expiresAt,deadline);
 session.uiUnlock.expiresAt=Date.now()-1;assert.equal(await recallKey(v,true),null);await assert.rejects(prepareRememberKey(created.key,created.salt,0),/отменена/);
 await rememberKey(created.key,created.salt,true,0,undefined,{freshAuthentication:true});assert.ok(session.uiUnlock.expiresAt>Date.now());
});
test('session mode choice persists immediately, wraps/removes device key and changes deadline on close',async()=>{
 reset();local={protectedMode:true};const created=await createKey('1234');await rememberKey(created.key,created.salt,true);const original={...session.uiUnlock};
 await changeSessionLifetime(created.key,created.salt,0,'synthetic-document');assert.equal(local.sessionLifetime,0);assert.equal(local.deviceKey.protection,'windows-dpapi');assert.equal(session.uiUnlock.expiresAt,original.expiresAt);
 await reconcileSessionPolicy('synthetic-document');assert.equal(session.uiUnlock.expiresAt,0);assert.equal(session.uiUnlock.authenticatedAt,original.authenticatedAt);
 await changeSessionLifetime(created.key,created.salt,30,'synthetic-document');assert.equal(local.deviceKey,undefined);assert.equal(session.uiUnlock.expiresAt,0);
 await reconcileSessionPolicy('synthetic-document');assert.equal(session.uiUnlock.expiresAt,original.authenticatedAt+30000);assert.equal(session.pendingSessionPolicy,undefined);
});
