const fs=require('node:fs');
const path=require('node:path');
const {chromium:realChromium}=require('playwright');
const work=path.resolve(__dirname,'../work');
fs.mkdirSync(work,{recursive:true});
const usedHomes=new Set(),contextHomes=new WeakMap();
async function launchPersistentContext(profile,options={}) {
  const requested=options.env?.USERPROFILE;
  const home=requested?path.resolve(requested):fs.mkdtempSync(path.join(work,'test-home-'));
  const relative=path.relative(work,home);
  if(!relative||relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative))throw new Error('Browser test USERPROFILE must be inside the project work directory');
  if(usedHomes.has(home.toLowerCase()))throw new Error('Each browser test context needs a unique USERPROFILE');
  usedHomes.add(home.toLowerCase());fs.mkdirSync(home,{recursive:true});
  const context=await realChromium.launchPersistentContext(profile,{...options,env:{...process.env,...options.env,USERPROFILE:home}});contextHomes.set(context,home);return context;
}
const chromium=new Proxy(realChromium,{get(target,name){if(name==='launchPersistentContext')return launchPersistentContext;const value=Reflect.get(target,name,target);return typeof value==='function'?value.bind(target):value;}});
// Exercise actual Windows DPAPI without registering a browser-wide native host.
// Only the two key-wrapping operations are accepted; this bridge cannot read/write files.
async function installDeviceKeyBridge(context){
 const home=contextHomes.get(context);if(!home)throw new Error('Use the isolated test browser before installing a device-key bridge');
 const exe=path.resolve(__dirname,'../native/CHROME-APP-TOTP.Host.exe');
 const source=fs.readFileSync(path.resolve(__dirname,'../native/Host.cs'),'utf8');
 const origin=source.match(/const string Origin = "([^"]+)"/)[1];
 await context.exposeFunction('__testRealDeviceKey',request=>{
  if(!request||!['protect-key','unprotect-key'].includes(request.op)||Object.keys(request).length!==2)throw new Error('Test bridge allows only device key wrapping');
  const field=request.op==='protect-key'?'key':'wrapped';if(typeof request[field]!=='string'||request[field].length>5464)throw new Error('Invalid synthetic key request');
  return new Promise((resolve,reject)=>{
   const child=require('node:child_process').spawn(exe,[origin],{windowsHide:true,env:{...process.env,USERPROFILE:home}});let output=Buffer.alloc(0),finished=false;
   const complete=(error,result)=>{if(finished)return;finished=true;clearTimeout(timer);error?reject(error):resolve(result);};
   const timer=setTimeout(()=>{child.kill();complete(new Error('DPAPI test helper timeout'));},10000);
   child.on('error',error=>complete(error));child.stderr.on('data',()=>complete(new Error('Unexpected DPAPI test stderr')));
   child.stdout.on('data',chunk=>{output=Buffer.concat([output,chunk]);if(output.length>16384){child.kill();complete(new Error('Oversized DPAPI test response'));}});
   child.on('close',code=>{try{if(code!==0||output.length<4||output.readUInt32LE(0)!==output.length-4)throw new Error('Invalid DPAPI test response');complete(null,JSON.parse(output.subarray(4).toString()));}catch(error){complete(error);}});
   child.stdin.on('error',()=>{});const data=Buffer.from(JSON.stringify(request)),header=Buffer.alloc(4);header.writeUInt32LE(data.length);child.stdin.end(Buffer.concat([header,data]));
  });
 });
 await context.addInitScript(()=>{chrome.runtime.connectNative=()=>{const messages=[],disconnects=[];let closed=false;return{onMessage:{addListener:fn=>messages.push(fn)},onDisconnect:{addListener:fn=>disconnects.push(fn)},disconnect(){closed=true;},postMessage(request){globalThis.__testRealDeviceKey(request).then(value=>{if(!closed)messages.forEach(fn=>fn(value));},()=>{if(!closed)messages.forEach(fn=>fn({ok:false,error:'Synthetic device-key bridge refused operation'}));});}};};});
}
module.exports={chromium,installDeviceKeyBridge};
