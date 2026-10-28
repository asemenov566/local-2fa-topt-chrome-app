import {normalizeAccount,decode32} from './core.js';

function varint(value) {
  const bytes=[]; let n=BigInt(value);
  do { const b=Number(n&127n); n>>=7n; bytes.push(b|(n?128:0)); } while(n);
  return bytes;
}
const field=(n,value)=>typeof value==='number' ? [...varint(n*8),...varint(value)] : [...varint(n*8+2),...varint(value.length),...value];
const utf8=text=>new TextEncoder().encode(text);
function payload(entries,size,index,batch) {
  const bytes=[...entries.flat(),...field(2,1),...field(3,size),...field(4,index),...field(5,batch)];
  return 'otpauth-migration://offline?data='+encodeURIComponent(btoa(bytes.map(b=>String.fromCharCode(b)).join('')));
}
export function migrationUris(records) {
  if (!records.length || records.length>2000) throw new Error('Выберите от 1 до 2000 аккаунтов.');
  const entries=records.map(record=>{
    const a=normalizeAccount(record);
    if(a.period!==30) throw new Error('Формат Google поддерживает период только 30 секунд. Для этих аккаунтов выберите «QR по одному».');
    const name=a.issuer ? a.issuer+':'+a.name : a.name;
    return field(1,[...field(1,decode32(a.secret)),...field(2,utf8(name)),...field(3,utf8(a.issuer)),...field(4,{SHA1:1,SHA256:2,SHA512:3}[a.algorithm]),...field(5,a.digits===6?1:2),...field(6,2)]);
  });
  const batch=crypto.getRandomValues(new Uint32Array(1))[0]&0x7fffffff;
  const groups=[]; let group=[];
  for(const entry of entries) {
    // Bound density, not just account count, so long UTF-8 labels also split.
    if(payload([entry],100,99,batch).length>1800) throw new Error('Один из аккаунтов слишком большой для QR. Используйте экспорт в файл.');
    if(group.length && (group.length>=10 || payload([...group,entry],100,99,batch).length>1000)) {groups.push(group);group=[];}
    group.push(entry);
  }
  if(group.length)groups.push(group);
  if(groups.length>100)throw new Error('Получается больше 100 QR. Экспортируйте аккаунты несколькими группами.');
  return groups.map((entries,index)=>({uri:payload(entries,groups.length,index,batch),count:entries.length}));
}
