const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {spawn} = require('node:child_process');
const root = path.resolve('.');
const exe = path.join(root,'native/CHROME-APP-TOTP.Host.exe');
const origin = 'chrome-extension://fgjoonbdgfdpjmpjbephffmkjackfgnp/';
function request(home,value,caller=origin) {
  return new Promise((resolve,reject) => {
    const child=spawn(exe,[caller],{env:{...process.env,USERPROFILE:home},windowsHide:true});
    let pending=Buffer.alloc(0),messages=[];
    const timeout=setTimeout(()=>{child.kill();reject(new Error('Host did not terminate'));},8000);
    child.on('error',reject);child.stderr.on('data',()=>reject(new Error('Unexpected native stderr')));
    child.stdout.on('data',chunk=>{
      pending=Buffer.concat([pending,chunk]);
      while(pending.length>=4&&pending.length>=pending.readUInt32LE(0)+4){const n=pending.readUInt32LE(0);assert.ok(n<1024*1024);messages.push(JSON.parse(pending.subarray(4,n+4)));pending=pending.subarray(n+4);}
    });
    child.on('close',code=>{clearTimeout(timeout);assert.equal(pending.length,0);resolve({code,messages,result:messages.at(-1),data:messages.filter(x=>x.chunk).map(x=>x.chunk).join('')});});
    child.stdin.on('error',()=>{});const bytes=Buffer.from(JSON.stringify(value));const header=Buffer.alloc(4);header.writeUInt32LE(bytes.length);child.stdin.end(Buffer.concat([header,bytes]));
  });
}
test('Native default creation, CAS, atomic writes, chunking and portability',async()=>{
  const {createKey,seal,unseal,vaultToken}=await import('../extension/vault.js');
  const {normalizeAccount}=await import('../extension/core.js');
  const home=await fs.mkdtemp(path.join(root,'work/native-home-'));
  const file=path.join(home,'.CHROME-APP-TOTP.vault');
  const status=await request(home,{op:'status'});assert.equal(status.result.path,file);assert.equal(status.result.exists,false);assert.equal(status.code,0);
  const password='123456',derived=await createKey(password);
  const accounts=[normalizeAccount({name:'Native test',secret:'JBSWY3DPEHPK3PXP',algorithm:'SHA1',digits:6,period:30})];
  const first=await seal(accounts,derived.key,derived.salt,1,6),data=JSON.stringify(first);
  assert.equal((await request(home,{op:'write',data,expectedToken:null})).result.ok,true);
  assert.deepEqual(JSON.parse(await fs.readFile(file,'utf8')),first);
  assert.equal((await request(home,{op:'write',data,expectedToken:null})).result.ok,false);
  const read=await request(home,{op:'read'});assert.equal(read.result.ok,true);assert.equal(read.data,data);
  const second=await seal(accounts,derived.key,derived.salt,2,6),third=await seal(accounts,derived.key,derived.salt,2,6);
  const races=await Promise.all([second,third].map(v=>request(home,{op:'write',data:JSON.stringify(v),expectedToken:vaultToken(first)})));
  assert.equal(races.filter(x=>x.result.ok).length,1);
  const saved=JSON.parse(await fs.readFile(file,'utf8'));assert.equal(saved.revision,2);
  const otherHome=await fs.mkdtemp(path.join(root,'work/native-other-pc-'));const otherFile=path.join(otherHome,'.CHROME-APP-TOTP.vault');
  await fs.copyFile(file,otherFile);const portable=await request(otherHome,{op:'read'});assert.equal((await unseal(JSON.parse(portable.data),password)).accounts[0].name,'Native test');
  await assert.rejects(unseal(JSON.parse(portable.data),'Wrong-master-password'));
  const invalid=path.join(home,'not-a-vault.json');await fs.writeFile(invalid,'{"personal":"unrelated file"}');
  assert.equal((await request(home,{op:'write',path:invalid,data,expectedToken:null})).result.ok,false);assert.equal(await fs.readFile(invalid,'utf8'),'{"personal":"unrelated file"}');
  for(const bad of ['relative.vault','\\\\server\\share\\file.vault','C:\\file.vault:ads','C:\\CON.vault','C:\\data.exe'])assert.equal((await request(home,{op:'write',path:bad,data,expectedToken:null})).result.ok,false);
  const large={...first,ciphertext:Buffer.alloc(1100000,7).toString('base64')};const largePath=path.join(home,'large.vault');
  assert.equal((await request(home,{op:'write',path:largePath,data:JSON.stringify(large),expectedToken:null})).result.ok,true);
  const chunks=await request(home,{op:'read',path:largePath});assert.ok(chunks.messages.length>2);assert.deepEqual(JSON.parse(chunks.data),large);
  const huge={...first,ciphertext:'A'.repeat(8000000)};assert.equal((await request(home,{op:'write',path:file,data:JSON.stringify(huge),expectedToken:vaultToken(saved)})).result.ok,false);assert.deepEqual(JSON.parse(await fs.readFile(file,'utf8')),saved);
  assert.equal((await request(home,{op:'status'},'chrome-extension://unrelated/')).messages.length,0);
  assert.equal((await request(home,{op:'delete'})).result.ok,false);
  assert.ok(!(await fs.readdir(home)).some(n=>n.endsWith('.tmp')));
});

test('Native accepts authenticated PIN length metadata and rejects unknown or mistyped fields',async()=>{
  const {createKey,seal,unseal,vaultToken}=await import('../extension/vault.js');
  const home=await fs.mkdtemp(path.join(root,'work/native-pin-home-'));
  for(const password of ['1234','abcdef']) {
    const derived=await createKey(password),v=await seal([],derived.key,derived.salt,1,derived.passwordLength);
    const file=path.join(home,'pin-'+password.length+'.vault');
    assert.equal((await request(home,{op:'write',path:file,data:JSON.stringify(v),expectedToken:null})).result.ok,true);
    const read=await request(home,{op:'read',path:file});assert.equal(read.result.ok,true);
    const restored=JSON.parse(read.data);assert.equal(restored.passwordLength,password.length);
    assert.equal((await unseal(restored,password)).passwordLength,password.length);
    for(const malformed of [{...v,passwordLength:5},{...v,passwordLength:'4'},{...v,passwordLength:null},{...v,passwordLength:true},{...v,passwordLength:4.01},{...v,unexpected:true}]) {
      assert.equal((await request(home,{op:'write',path:file,data:JSON.stringify(malformed),expectedToken:vaultToken(v)})).result.ok,false);
      assert.deepEqual(JSON.parse(await fs.readFile(file,'utf8')),v);
    }
    const old={...v};delete old.passwordLength;
    assert.equal((await request(home,{op:'write',path:file,data:JSON.stringify(old),expectedToken:vaultToken(v)})).result.ok,false);
    assert.equal((await request(home,{op:'write',path:file,data:JSON.stringify({...old,unexpected:4}),expectedToken:vaultToken(v)})).result.ok,false);
    assert.deepEqual(JSON.parse(await fs.readFile(file,'utf8')),v);
    const oldFile=path.join(home,'missing-length-'+password.length+'.vault');
    await fs.writeFile(oldFile,JSON.stringify(old));
    assert.equal((await request(home,{op:'read',path:oldFile})).result.ok,false);
  }
});

test('Native DPAPI wraps only 32-byte device keys and rejects malformed or tampered blobs',async()=>{
  const home=await fs.mkdtemp(path.join(root,'work/native-dpapi-home-'));
  const key=Buffer.alloc(32,37).toString('base64');
  const protectedResult=await request(home,{op:'protect-key',key});
  assert.equal(protectedResult.result.ok,true);
  const wrapped=protectedResult.result.wrapped;
  assert.equal(typeof wrapped,'string');assert.notEqual(wrapped,key);
  assert.equal(protectedResult.result.key,undefined);
  // request() starts a new process: successful unwrap does not depend on helper lifetime.
  const reopened=await request(home,{op:'unprotect-key',wrapped});
  assert.equal(reopened.result.ok,true);assert.equal(reopened.result.key,key);
  const mutated=Buffer.from(wrapped,'base64');mutated[mutated.length-1]^=1;
  for(const value of [
    {op:'protect-key',key:Buffer.alloc(31).toString('base64')},
    {op:'protect-key',key:Buffer.alloc(33).toString('base64')},
    {op:'protect-key',key:' '+key},
    {op:'protect-key',key,path:'C:\\ignored.vault'},
    {op:'protect-key',key:null},
    {op:'unprotect-key',wrapped:mutated.toString('base64')},
    {op:'unprotect-key',wrapped:Buffer.alloc(32).toString('base64')},
    {op:'unprotect-key',wrapped:'A'.repeat(5465)},
    {op:'unprotect-key',wrapped,extra:true}
  ]){const rejected=await request(home,value);assert.equal(rejected.result.ok,false);assert.equal(rejected.result.key,undefined);assert.equal(rejected.result.wrapped,undefined);}
  assert.equal((await request(home,{op:'unprotect-key',wrapped},'chrome-extension://unrelated/')).messages.length,0);
  assert.equal((await fs.readdir(home)).some(name=>name.endsWith('.vault')),false,'DPAPI operations must not create any vault');
});
