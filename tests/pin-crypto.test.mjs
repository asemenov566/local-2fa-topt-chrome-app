import test from 'node:test';
import assert from 'node:assert/strict';
import {createKey,seal,unseal,validateEnvelope} from '../extension/vault.js';
import {attemptPassword,getPasswordGate} from '../extension/auth-attempts.js';

let store={},lockChain=Promise.resolve();
globalThis.chrome={storage:{local:{
  async get(name){return {[name]:structuredClone(store[name])};},
  async set(values){Object.assign(store,structuredClone(values));},
  async remove(name){delete store[name];}
}}};
Object.defineProperty(navigator,'locks',{configurable:true,value:{request(name,callback){
  const work=lockChain.then(callback);lockChain=work.catch(()=>{});return work;
}}});

test('4/6/12 character metadata survives portable encryption and is authenticated',async()=>{
 for(const password of ['1234','aB!кж6','🔒🔑aб','aБ!2🔒xyz-9К?']) {
  const created=await createKey(password),length=Array.from(password).length;
  assert.equal(created.passwordLength,length);
  const envelope=await seal([],created.key,created.salt,1,created.passwordLength);
  const reopened=await unseal(JSON.parse(JSON.stringify(envelope)),password);
  assert.equal(reopened.passwordLength,length);
  const tampered={...envelope,passwordLength:length===4?6:4};
  await assert.rejects(unseal(tampered,password),e=>e.code==='INVALID_PASSWORD');
  const removed={...envelope};delete removed.passwordLength;
  await assert.rejects(unseal(removed,password),/длина код-пароля/);
  assert.throws(()=>validateEnvelope({...envelope,passwordLength:5}));
 }
 for(const invalid of ['','123','12345','1234567','Legacy-long-password-2026'])await assert.rejects(createKey(invalid),/4, 6 или 12/);
 const created=await createKey('1234');
 await assert.rejects(seal([],created.key,created.salt,1),/длина код-пароля/);
});

test('three wrong attempts share a persistent 60-second gate, success clears it',async()=>{
 store={};const created=await createKey('123456'),v=await seal([],created.key,created.salt,1,6);
 const realNow=Date.now;let now=1800000000000;Date.now=()=>now;
 try {
  await assert.rejects(attemptPassword(v,'111111'),e=>e.code==='INVALID_PASSWORD'&&e.failures===1);
  await assert.rejects(attemptPassword(v,'222222'),e=>e.code==='INVALID_PASSWORD'&&e.failures===2);
  await assert.rejects(attemptPassword(v,'333333'),e=>e.code==='PASSWORD_BLOCKED'&&e.blockedUntil===now+60000);
  const persisted=JSON.parse(JSON.stringify(store));
  store=persisted;
  assert.deepEqual(await getPasswordGate(v),{failures:3,blockedUntil:now+60000});
  await assert.rejects(attemptPassword(v,'123456'),e=>e.code==='PASSWORD_BLOCKED');
  now+=59999;await assert.rejects(attemptPassword(v,'123456'),e=>e.code==='PASSWORD_BLOCKED');
  now++;assert.deepEqual(await getPasswordGate(v),{failures:0,blockedUntil:0});
  await attemptPassword(v,'123456');assert.equal(store.passwordAttemptGate,undefined);
  const serialized=JSON.stringify(persisted);assert.equal(serialized.includes('111111'),false);assert.equal(serialized.includes('123456'),false);
 } finally {Date.now=realNow;}
});

test('concurrent popup attempts serialize; malformed data does not count',async()=>{
 store={};const created=await createKey('ABCD'),v=await seal([],created.key,created.salt,1,4);
 await assert.rejects(attemptPassword({...v,iv:'broken'},'xxxx'));assert.equal(store.passwordAttemptGate,undefined);
 const results=await Promise.allSettled(Array.from({length:4},()=>attemptPassword(v,'xxxx')));
 assert.ok(results.every(r=>r.status==='rejected'));
 assert.deepEqual(results.map(r=>r.reason.code),['INVALID_PASSWORD','INVALID_PASSWORD','PASSWORD_BLOCKED','PASSWORD_BLOCKED']);
 assert.equal((await getPasswordGate(v)).failures,3);
 const other=await createKey('EFGH'),v2=await seal([],other.key,other.salt,1,4);
 await attemptPassword(v2,'EFGH');
 assert.equal((await getPasswordGate(v)).failures,3);
});
