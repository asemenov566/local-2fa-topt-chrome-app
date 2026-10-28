import test from 'node:test';
import assert from 'node:assert/strict';
import {encode32,decode32,normalizeAccount,normalizeBinding,validateBindings,totp,hotp,parseOtp,otpUri,parseMigration,MigrationBatch,parseBackup,exportText} from '../extension/core.js';
import {createKey,seal,unseal,validateEnvelope} from '../extension/vault.js';
import {migrationUris} from '../extension/migration-export.js';
import QRCode from 'qrcode';
export const secret=encode32(new TextEncoder().encode('12345678901234567890'));
export const account={name:'Synthetic test',issuer:'Example',secret,algorithm:'SHA1',digits:6,period:30,type:'totp'};
const vint=n=>{n=BigInt(n);const b=[];do{let x=Number(n&127n);n>>=7n;b.push(x|(n?128:0));}while(n);return b;};
const field=(n,value)=> typeof value==='number'? [...vint(n*8),...vint(value)] : [...vint(n*8+2),...vint(value.length),...value];
const str=s=>[...new TextEncoder().encode(s)];
export function migration({index=0,size=1,batch=42,type=2,name='Synthetic test',algorithm=1,digits=1,version=1}={}) {
 const entry=[...field(1,[...decode32(secret)]),...field(2,str(name)),...field(3,str('Example')),...field(4,algorithm),...field(5,digits),...field(6,type)];
 const bytes=[...field(1,entry),...(version===null?[]:field(2,version)),...(size===null?[]:field(3,size)),...(index===null?[]:field(4,index)),...(batch===null?[]:field(5,batch))];
 return 'otpauth-migration://offline?data='+encodeURIComponent(Buffer.from(bytes).toString('base64'));
}
test('RFC 6238: all 18 vectors SHA1/256/512, including time >2038',async()=>{
 const times=[59,1111111109,1111111111,1234567890,2000000000,20000000000];
 const expected={SHA1:['94287082','07081804','14050471','89005924','69279037','65353130'],SHA256:['46119246','68084774','67062674','91819424','90698825','77737706'],SHA512:['90693936','25091201','99943326','93441116','38618901','47863826']};
 for(const [algorithm,len] of [['SHA1',20],['SHA256',32],['SHA512',64]]) for(let i=0;i<times.length;i++) assert.equal(await totp({...account,algorithm,digits:8,secret:encode32(str('1234567890'.repeat(7).slice(0,len)))},times[i]*1000),expected[algorithm][i]);
});
test('RFC 4226: ten counter vectors',async()=>{const expected=['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];for(let i=0;i<10;i++)assert.equal(await hotp(secret,i),expected[i]);});
test('Base32 canonical round trips and malformed encodings',()=>{for(let i=1;i<80;i++){const bytes=crypto.getRandomValues(new Uint8Array(i));assert.deepEqual(decode32(encode32(bytes)),bytes);}for(const s of ['A','ABC','ABCDEF','MZ','MZXW6===X','00000000','MY=',''])assert.throws(()=>decode32(s));assert.equal(encode32(decode32('my======')),'MY');});
test('otpauth parameters survive parsing/export, unsafe unsupported rejected',()=>{const a=normalizeAccount({...account,name:'a+b@example.ru',issuer:'Тест',algorithm:'SHA512',digits:8,period:45});const b=parseOtp(otpUri(a));for(const k of ['name','issuer','secret','algorithm','digits','period'])assert.equal(a[k],b[k]);for(const u of ['otpauth://hotp/X?secret='+secret,'otpauth://totp/X?secret='+secret+'&digits=7','otpauth://totp/X?secret='+secret+'&period=0','otpauth://totp/X?secret='+secret+'&secret='+secret,'otpauth://totp/A:B?issuer=C&secret='+secret])assert.throws(()=>parseOtp(u));});
test('migration order, missing parts, duplicate part and conflicting batch',()=>{const b=new MigrationBatch();let s=b.add(parseMigration(migration({index:1,size:2,name:'Two'})));assert.deepEqual(s.missing,[0]);assert.equal(s.complete,false);assert.equal(b.add(parseMigration(migration({index:1,size:2,name:'Two'}))).duplicate,true);assert.throws(()=>b.add(parseMigration(migration({index:1,size:2,name:'Different'}))));assert.throws(()=>b.add(parseMigration(migration({size:2,batch:99}))));s=b.add(parseMigration(migration({size:2,name:'One'})));assert.equal(s.complete,true);assert.deepEqual(b.collect().map(a=>a.name),['One','Two']);});
test('HOTP and unsupported algorithms explicitly reported; malformed protobuf rejected',()=>{assert.match(parseMigration(migration({type:1})).warnings[0],/HOTP/);assert.equal(parseMigration(migration({algorithm:4})).accounts.length,0);for(const value of [migration({version:2147483648}),migration({index:2,size:2}),'otpauth-migration://offline?data=!!!!','otpauth-migration://offline?data=Cv8%3D','otpauth-migration://offline?data=gA%3D%3D'])assert.throws(()=>parseMigration(value));});
test('Google exports use validated records with optional version/batch metadata',()=>{
 for(const version of [null,0,1,2,99]) {
  const p=parseMigration(migration({version}));assert.equal(p.accounts[0].secret,secret);assert.equal(p.accounts[0].algorithm,'SHA1');
 }
 for(const size of [null,0]) {const p=parseMigration(migration({version:null,size,index:null,batch:null}));assert.equal(p.size,0);assert.equal(p.index,0);assert.equal(p.accounts.length,1);}
 for(const input of [{size:0,index:1},{size:101},{size:2,index:2}])assert.throws(()=>parseMigration(migration(input)));
 const defaults=parseMigration(migration({algorithm:0,digits:0,type:0})).accounts[0];assert.equal(defaults.algorithm,'SHA1');assert.equal(defaults.digits,6);assert.equal(defaults.type,'totp');
 for(const input of [{algorithm:99},{digits:99},{type:99}]) {const p=parseMigration(migration(input));assert.equal(p.accounts.length,0);assert.equal(p.warnings.length,1);}
});
test('encrypted vault round trip, wrong password, tamper, unique IV',async()=>{const {key,salt}=await createKey('123456');const a=normalizeAccount(account);const v=await seal([a],key,salt,1,6);assert.ok(!JSON.stringify(v).includes(secret));assert.deepEqual((await unseal(v,'123456')).accounts,[a]);await assert.rejects(unseal(v,'wrong'));await assert.rejects(unseal({...v,revision:2},'123456'));const v2=await seal([a],key,salt,2,6);assert.notEqual(v.iv,v2.iv);assert.throws(()=>validateEnvelope({...v,iterations:1}));});
test('JSON/TXT export retains key and parameters',()=>{const a=normalizeAccount(account);assert.equal(parseBackup(JSON.stringify({format:'chrome-app-totp-plain',version:1,accounts:[a]}))[0].secret,secret);assert.ok(exportText([a]).includes(otpUri(a)));});
test('Transfer URI safely handles colons in display names',()=>{for(const values of [{name:'work:mail',issuer:''},{name:'a:b',issuer:'ACME:team'}]){const a=normalizeAccount({...account,...values});const b=parseOtp(otpUri(a));for(const k of ['secret','algorithm','digits','period'])assert.equal(a[k],b[k]);assert.equal(b.name,a.name.replaceAll(':',' · '));assert.equal(b.issuer,a.issuer.replaceAll(':',' · '));assert.equal(a.name,values.name);}});
test('bindings are exact HTTPS origins and unique; Gosuslugi singleton',()=>{assert.deepEqual(normalizeBinding({service:'gosuslugi'}),{service:'gosuslugi',origin:'https://esia.gosuslugi.ru'});assert.equal(normalizeBinding({service:'bitrix',origin:'https://other.example.ru/path?login=yes'}).origin,'https://other.example.ru');for(const origin of ['http://example.ru','https://u:p@example.ru','https://example.ru:8443'])assert.throws(()=>normalizeBinding({service:'bitrix',origin}));assert.throws(()=>validateBindings([{binding:{origin:'https://a.ru'}},{binding:{origin:'https://a.ru'}}]));});

test('Google QR export restores all multipart records in order without local metadata',()=>{
 const original=Array.from({length:27},(_,i)=>normalizeAccount({...account,name:'Account '+i,secret:encode32(str('Synthetic secret '+i)),binding:{service:'bitrix',origin:'https://example.org'}}));
 const parts=migrationUris(original), batch=new MigrationBatch();
 assert.ok(parts.length>1);
 const decoded=parts.map(p=>parseMigration(p.uri));
 assert.equal(new Set(decoded.map(p=>p.batch)).size,1);
 for(let i=0;i<parts.length;i++) {
  const p=decoded[i]; assert.equal(p.version,1); assert.equal(p.size,parts.length); assert.equal(p.index,i);
  assert.ok(BigInt(p.batch)>=0n && BigInt(p.batch)<=2147483647n);
  assert.equal(parts[i].count,p.accounts.length); assert.ok(parts[i].count<=10); assert.deepEqual(p.warnings,[]);
 }
 for(const p of [...decoded].reverse()) batch.add(p);
 assert.equal(batch.add(decoded[0]).duplicate,true);
 const restored=batch.collect(); assert.equal(restored.length,original.length);
 for(let i=0;i<original.length;i++) {
  for(const key of ['name','issuer','secret','algorithm','digits','period','type'])assert.equal(restored[i][key],original[i][key]);
  assert.equal(restored[i].binding,null);
 }
});

test('Google QR export preserves every supported algorithm and digit count, including actual codes',async()=>{
 const original=['SHA1','SHA256','SHA512'].flatMap(algorithm=>[6,8].map(digits=>({...account,algorithm,digits,name:algorithm+' '+digits})));
 const restored=migrationUris(original).flatMap(p=>parseMigration(p.uri).accounts);
 for(let i=0;i<original.length;i++) {
  assert.equal(restored[i].algorithm,original[i].algorithm); assert.equal(restored[i].digits,original[i].digits);
  for(const time of [59000,1234567890000,20000000000000])assert.equal(await totp(restored[i],time),await totp(original[i],time));
 }
 const p=parseMigration(migrationUris([account])[0].uri);
 // Compare wire bytes with a separately assembled schema fixture, not just our decoder.
 assert.equal(p.signature,parseMigration(migration({name:'Example:Synthetic test',batch:Number(p.batch)})).signature);
 for(const period of [1,29,31,45,60,86400])assert.throws(()=>migrationUris([account,{...account,period}]),/30/);
 assert.throws(()=>migrationUris([{...account,type:'hotp'}]),/HOTP/);
});

test('Google QR export sizes UTF-8 labels by encoded payload and remains QR-encodable',()=>{
 const long={...account,name:'Ж'.repeat(200),issuer:'界'.repeat(100)};
 const original=[long,{...long,name:'Я'.repeat(200)}, {...account,name:'mail:work 😀',issuer:'ACME:世界'}];
 const parts=migrationUris(original), restored=parts.flatMap(p=>parseMigration(p.uri).accounts);
 assert.ok(parts.length>=2);
 for(let i=0;i<original.length;i++)for(const k of ['name','issuer','secret'])assert.equal(restored[i][k],original[i][k]);
 for(const p of parts) {
  assert.ok(p.uri.length<=1800); if(p.count>1)assert.ok(p.uri.length<=1000);
  assert.ok(QRCode.create(p.uri,{errorCorrectionLevel:'M'}).modules.size>0);
 }
 assert.throws(()=>migrationUris([{...account,name:'界'.repeat(300),issuer:'界'.repeat(300)}]),/слишком большой/);
 assert.equal(migrationUris(Array.from({length:100},()=>long)).length,100);
 assert.throws(()=>migrationUris(Array.from({length:101},()=>long)),/100 QR/);
 assert.throws(()=>migrationUris([])); assert.throws(()=>migrationUris(Array(2001).fill(account)));
});
