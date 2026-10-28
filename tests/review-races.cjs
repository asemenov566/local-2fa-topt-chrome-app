const path=require('node:path');
const {chromium}=require('./test-browser.cjs');
(async()=>{
 const root=path.resolve('.'), ext=path.join(root,'extension');
 const context=await chromium.launchPersistentContext(path.join(root,'work/review-races-profile-'+Date.now()),{executablePath:(process.env.TOTP_CHROMIUM_PATH || chromium.executablePath()),headless:true,args:[`--disable-extensions-except=${ext}`,`--load-extension=${ext}`]});
 try {
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');const id=worker.url().split('/')[2];const page=await context.newPage();await page.goto(`chrome-extension://${id}/package.json`);
  console.log('RACE RESULTS',await page.evaluate(async()=>{
   const v=await import('./vault.js'),s=await import('./security.js');
   const dir=await navigator.storage.getDirectory();const a=await dir.getFileHandle('REVIEW-A.json',{create:true}),b=await dir.getFileHandle('REVIEW-B.json',{create:true});
   const ka=await v.createKey('246813'),kb=await v.createKey('975310');
   const a1=await v.seal([],ka.key,ka.salt,1,ka.passwordLength),a2=await v.seal([],ka.key,ka.salt,2,ka.passwordLength),b1=await v.seal([],kb.key,kb.salt,1,kb.passwordLength);
   for(const [h,data]of [[a,a1],[b,b1]]){const w=await h.createWritable();await w.write(JSON.stringify(data));await w.close();}
   await v.attachHandle(a);
   const getFile=FileSystemFileHandle.prototype.getFile;let reached,release;
   const reachedPromise=new Promise(r=>reached=r);
   FileSystemFileHandle.prototype.getFile=async function(){const file=await getFile.call(this);if(this.name==='REVIEW-A.json'){reached();return new Promise(r=>release=()=>r(file));}return file;};
   const save=v.saveVault(a2,v.vaultToken(a1));await reachedPromise;const switching=v.attachHandle(b);release();await save;await switching;FileSystemFileHandle.prototype.getFile=getFile;
   const bAfter=JSON.parse(await(await b.getFile()).text());
   await chrome.storage.local.set({protectedMode:true});await chrome.storage.session.set({manualLock:false,lockEpoch:0});
   const exportKey=crypto.subtle.exportKey.bind(crypto.subtle);let exportReached,exportRelease;
   const exportReachedPromise=new Promise(r=>exportReached=r);
   crypto.subtle.exportKey=async(...args)=>{const raw=await exportKey(...args);exportReached();return new Promise(r=>exportRelease=()=>r(raw));};
   const remember=s.rememberKey(ka.key,ka.salt,true,0).then(()=>({rejected:false}),()=>({rejected:true}));await exportReachedPromise;
   await navigator.locks.request('chrome-app-totp-security',async()=>{await chrome.storage.session.remove('uiUnlock');await chrome.storage.session.set({manualLock:true,lockEpoch:1});});
   exportRelease();const rememberResult=await remember;crypto.subtle.exportKey=exportKey;
   const session=await chrome.storage.session.get(['manualLock','uiUnlock']);
   const result={fileBWasOverwrittenWithA:v.vaultToken(bAfter)===v.vaultToken(a2),lockedSessionWasReopened:session.manualLock===false&&!!session.uiUnlock,staleUnlockRejected:rememberResult.rejected};
   if(result.fileBWasOverwrittenWithA||result.lockedSessionWasReopened||!result.staleUnlockRejected)throw new Error('Concurrency security regression');
   return result;
  }));
 }finally{await context.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
