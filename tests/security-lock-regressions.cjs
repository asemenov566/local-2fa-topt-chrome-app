const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs/promises');
const {randomBytes}=require('node:crypto');
const {chromium}=require('./test-browser.cjs');
const root=path.resolve(__dirname,'..'),source=path.join(root,'extension');
function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
async function bounded(promise,message){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error(message)),5000);})]);}finally{clearTimeout(timer);}}
async function launch(extension=source){return chromium.launchPersistentContext(path.join(root,'work/security-regression-'+Date.now()+'-'+randomBytes(4).toString('hex')),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:['--load-extension='+extension,'--disable-extensions-except='+extension],viewport:{width:410,height:780}});}
async function address(context){const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');return {worker,base:'chrome-extension://'+worker.url().split('/')[2]+'/'};}
async function nativeMock(context,handler){
 await context.exposeFunction('__testDeviceKey',handler);
 await context.addInitScript(()=>{chrome.runtime.connectNative=()=>{const callbacks=[];return {onMessage:{addListener:fn=>callbacks.push(fn)},onDisconnect:{addListener(){}},disconnect(){},postMessage(request){globalThis.__testDeviceKey(request).then(result=>callbacks.forEach(fn=>fn(result)),()=>callbacks.forEach(fn=>fn({ok:false,error:'Synthetic native failure'})));}};};});
}
async function seed(page,base,{convenience=false,binding=null,file='SYNTHETIC.vault'}={}){
 await page.goto(base+'package.json');
 await page.evaluate(async({convenience,binding,file})=>{
  const v=await import('./vault.js'),s=await import('./security.js'),{normalizeAccount}=await import('./core.js');
  const h=await(await navigator.storage.getDirectory()).getFileHandle(file,{create:true});await v.attachHandle(h);
  const key=await v.createKey('1234');
  const account=normalizeAccount({name:'Synthetic regression account',secret:'JBSWY3DPEHPK3PXP',...(binding?{binding}:{})});
  await v.saveVault(await v.seal([account],key.key,key.salt,1,4),null);
  await chrome.storage.local.set({protectedMode:!convenience,autoEnabled:!!binding});await s.rememberKey(key.key,key.salt,!convenience);
 },{convenience,binding,file});
 await page.goto(base+'app.html?full=1');await page.locator('.code').waitFor({state:'visible'});
}
async function failedPasswordChange(){
 const context=await launch(),wrappers=new Map();let fail=false;
 try{
  await nativeMock(context,request=>{
   if(request.op==='protect-key'){if(fail)return {ok:false,error:'Synthetic protect failure'};const wrapped=randomBytes(48).toString('base64');wrappers.set(wrapped,request.key);return {ok:true,wrapped};}
   if(request.op==='unprotect-key'&&wrappers.has(request.wrapped))return {ok:true,key:wrappers.get(request.wrapped)};
   return {ok:false,error:'Unexpected synthetic native operation'};
  });
  const {base}=await address(context),page=await context.newPage();await seed(page,base,{convenience:true});
  await page.evaluate(async()=>{globalThis.beforeChange={file:JSON.stringify(await(await import('./vault.js')).loadVault()),wrapper:JSON.stringify((await chrome.storage.local.get('deviceKey')).deviceKey)};});
  await page.locator('#settings-button').click();await page.locator('#change-password-open').click();
  await page.locator('#old-password').fill('1234');await page.locator('#new-password-length').selectOption('4');
  await page.locator('#new-password').fill('4321');await page.locator('#new-password-confirm').fill('4321');fail=true;
  await page.locator('#change-password-form button.primary').click();await page.waitForFunction(()=>document.querySelector('#password-error').textContent.includes('Synthetic'));
  const outcome=await page.evaluate(async()=>{
   const v=await import('./vault.js'),current=await v.loadVault();let oldOpens=false,newOpens=false;
   try{await v.unseal(current,'1234');oldOpens=true;}catch{}try{await v.unseal(current,'4321');newOpens=true;}catch{}
   return {oldOpens,newOpens,fileUnchanged:JSON.stringify(current)===beforeChange.file,wrapperUnchanged:JSON.stringify((await chrome.storage.local.get('deviceKey')).deviceKey)===beforeChange.wrapper,dialogOpen:document.querySelector('#password-dialog').open};
  });
  assert.deepEqual(outcome,{oldOpens:true,newOpens:false,fileUnchanged:true,wrapperUnchanged:true,dialogOpen:true});
  console.log('PASS failed DPAPI preparation leaves previous password, encrypted file and device wrapper intact');
 }finally{await context.close();}
}
async function delayedProtectLock(){
 const context=await launch(),entered=deferred(),release=deferred();
 try{
  await nativeMock(context,async request=>{if(request.op==='protect-key'){entered.resolve();await release.promise;return {ok:true,wrapped:randomBytes(48).toString('base64')};}return {ok:false,error:'Unexpected synthetic native operation'};});
  const {base}=await address(context),first=await context.newPage();await seed(first,base);
  const second=await context.newPage();await second.goto(base+'app.html?full=1');await second.locator('.code').waitFor({state:'visible'});
  await first.locator('#settings-button').click();await first.locator('#session-lifetime').selectOption('0');await bounded(entered.promise,'DPAPI protect request was not reached');
  await first.locator('#settings-dialog .close').click();await first.locator('#lock-button').click();
  await second.locator('#codes-screen').waitFor({state:'hidden',timeout:1500});
  assert.deepEqual(await second.evaluate(async()=>{const s=await chrome.storage.session.get(['manualLock','uiUnlock']);return {locked:s.manualLock===true,noKey:!s.uiUnlock,noCode:!document.querySelector('.code')};}),{locked:true,noKey:true,noCode:true});
  release.resolve();await first.waitForFunction(()=>!document.querySelector('#session-lifetime').disabled);
  assert.equal(await second.evaluate(async()=>!(await chrome.storage.session.get('uiUnlock')).uiUnlock),true);
  console.log('PASS delayed DPAPI response does not delay locking the other window or restore its unlocked session');
 }finally{release.resolve();await context.close();}
}
async function delayedOtpReadLock(){
 const extension=path.join(root,'work/security-io-extension-'+Date.now());await fs.cp(source,extension,{recursive:true});
 const manifest=JSON.parse(await fs.readFile(path.join(extension,'manifest.json'),'utf8'));
 manifest.host_permissions=['https://security-regression.example.test/*'];await fs.writeFile(path.join(extension,'manifest.json'),JSON.stringify(manifest));
 const context=await launch(extension);let worker;
 try{
  const info=await address(context);worker=info.worker;const {base}=info,first=await context.newPage();
  await seed(first,base,{binding:{service:'bitrix',origin:'https://security-regression.example.test'},file:'SYNTHETIC-IO.vault'});
  const second=await context.newPage();await second.goto(base+'app.html?full=1');await second.locator('.code').waitFor({state:'visible'});
  await context.route('https://security-regression.example.test/**',route=>route.fulfill({contentType:'text/html',body:'<!doctype html><meta charset="utf-8"><form name="form_auth"><input name="USER_LOGIN"><button type="button" id="login">Войти</button><div id="otp"></div></form><script>document.getElementById("login").onclick=()=>document.getElementById("otp").innerHTML="<input name=USER_OTP>";</script>'}));
  const site=await context.newPage();await site.goto('https://security-regression.example.test/login/');
  await worker.evaluate(()=>{
   const original=FileSystemFileHandle.prototype.getFile;let entered;
   globalThis.testReadEntered=new Promise(resolve=>{entered=resolve;});
   FileSystemFileHandle.prototype.getFile=async function(...args){const file=await original.apply(this,args);if(this.name==='SYNTHETIC-IO.vault'){entered();await new Promise(resolve=>{globalThis.testReleaseRead=resolve;});}return file;};
  });
  await site.locator('#login').click();await bounded(worker.evaluate(()=>globalThis.testReadEntered),'OTP file read was not reached');
  await first.locator('#lock-button').click();await second.locator('#codes-screen').waitFor({state:'hidden',timeout:1500});
  assert.deepEqual(await second.evaluate(async()=>{const s=await chrome.storage.session.get(['manualLock','uiUnlock','autofillSession']);return {locked:s.manualLock===true,noKey:!s.uiUnlock,noAutofill:!s.autofillSession};}),{locked:true,noKey:true,noAutofill:true});
  await worker.evaluate(()=>globalThis.testReleaseRead());
  // Status is serialized behind the pending OTP action, so its response is a completion barrier.
  await first.evaluate(()=>chrome.runtime.sendMessage({type:'status'}));
  await site.evaluate(()=>new Promise(resolve=>requestAnimationFrame(resolve)));
  assert.equal(await site.locator('[name=USER_OTP]').inputValue(),'');
  assert.equal(await second.evaluate(()=>document.querySelector('#codes-screen').hidden),true);
  console.log('PASS delayed OTP file read cannot postpone lock or insert a code after locking');
 }finally{try{await worker?.evaluate(()=>globalThis.testReleaseRead?.());}catch{}await context.close();}
}
async function passwordCommittedAtExpiry(){
 const context=await launch();
 try {
  const {worker,base}=await address(context),page=await context.newPage();await seed(page,base,{file:'SYNTHETIC-COMMIT.vault'});
  // Isolate the commit/rememberKey race from the independent alarm and UI timeout.
  await worker.evaluate(async()=>{chrome.alarms.create=async()=>{};await chrome.alarms.clear('totp-session-expiry');});
  await page.locator('#settings-button').click();await page.locator('#change-password-open').click();await page.locator('#new-password-length').selectOption('4');
  await page.locator('#new-password').fill('4321');await page.locator('#new-password-confirm').fill('4321');
  await page.evaluate(async()=>{
   const send=chrome.runtime.sendMessage.bind(chrome.runtime);chrome.runtime.sendMessage=m=>m?.type==='session-expire'?new Promise(()=>{}):send(m);
   const close=FileSystemWritableFileStream.prototype.close;FileSystemWritableFileStream.prototype.close=async function(...args){await close.apply(this,args);await new Promise(resolve=>setTimeout(resolve,1200));};
   const {uiUnlock}=await chrome.storage.session.get('uiUnlock');await chrome.storage.session.set({uiUnlock:{...uiUnlock,expiresAt:Date.now()+1000}});
  });
  await page.locator('#change-password-form button.primary').click();await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Пароль изменён. Сессия завершена.'));
  const result=await page.evaluate(async()=>{
   const v=await import('./vault.js'),file=await v.loadVault(),session=await chrome.storage.session.get(['uiUnlock','manualLock']);let oldOpens=false,newOpens=false;
   try{await v.unseal(file,'1234');oldOpens=true;}catch{}try{await v.unseal(file,'4321');newOpens=true;}catch{}
   return {oldOpens,newOpens,locked:session.manualLock===true,noKey:!session.uiUnlock,dialogOpen:document.querySelector('#password-dialog').open,error:document.querySelector('#password-error').textContent};
  });
  assert.deepEqual(result,{oldOpens:false,newOpens:true,locked:true,noKey:true,dialogOpen:false,error:''});
  console.log('PASS password committed at expiry is reported saved and locked, with new password active and no revived key');
 } finally {await context.close();}
}
async function stalePasswordCommitPreservesFreshLogin(){
 const context=await launch(),entered=deferred(),release=deferred();
 try {
  const {base}=await address(context),first=await context.newPage();await seed(first,base,{file:'SYNTHETIC-NEW-LOGIN.vault'});
  await context.exposeFunction('__testAfterDiskCommit',()=>{entered.resolve();return release.promise;});
  await first.evaluate(()=>{const close=FileSystemWritableFileStream.prototype.close;FileSystemWritableFileStream.prototype.close=async function(...args){await close.apply(this,args);await globalThis.__testAfterDiskCommit();};});
  await first.locator('#settings-button').click();await first.locator('#change-password-open').click();await first.locator('#new-password-length').selectOption('4');
  await first.locator('#new-password').fill('5678');await first.locator('#new-password-confirm').fill('5678');await first.locator('#change-password-form button.primary').click();
  await bounded(entered.promise,'Password file commit was not reached');
  const second=await context.newPage();await second.goto(base+'app.html?full=1');await second.locator('#password').fill('5678');await second.locator('#codes-screen').waitFor({state:'visible'});
  const fresh=await second.evaluate(async()=>{const {uiUnlock,lockEpoch}=await chrome.storage.session.get(['uiUnlock','lockEpoch']);return {authenticatedAt:uiUnlock.authenticatedAt,salt:uiUnlock.salt,lockEpoch};});
  release.resolve();await first.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Пароль изменён. Сессия завершена.'));
  const after=await second.evaluate(async()=>{const {uiUnlock,lockEpoch}=await chrome.storage.session.get(['uiUnlock','lockEpoch']);return {authenticatedAt:uiUnlock?.authenticatedAt,salt:uiUnlock?.salt,lockEpoch};});
  assert.deepEqual(after,fresh);assert.equal(await second.locator('#codes-screen').isVisible(),true);assert.equal(await first.locator('#codes-screen').isVisible(),false);
  console.log('PASS late completion of old password save never locks a fresh login in another window');
 } finally {release.resolve();await context.close();}
}
(async()=>{await failedPasswordChange();await delayedProtectLock();await delayedOtpReadLock();await passwordCommittedAtExpiry();await stalePasswordCommitPreservesFreshLogin();})().catch(error=>{console.error(error);process.exitCode=1;});
