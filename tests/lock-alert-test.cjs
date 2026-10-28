const assert=require('node:assert/strict'),path=require('node:path'),{chromium}=require('./test-browser.cjs');
(async()=>{
 const ext=path.resolve('extension'),context=await chromium.launchPersistentContext(path.resolve('work/lock-alert-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:['--load-extension='+ext,'--disable-extensions-except='+ext],viewport:{width:390,height:240}});
 try{
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),base='chrome-extension://'+worker.url().split('/')[2]+'/',setup=await context.newPage();
  await setup.goto(base+'package.json');
  await setup.evaluate(async()=>{const v=await import('./vault.js'),h=await(await navigator.storage.getDirectory()).getFileHandle('ALERT-TEST.vault',{create:true});await v.attachHandle(h);const k=await v.createKey('2468');globalThis.syntheticEnvelope=await v.seal([],k.key,k.salt,1,4);await v.saveVault(syntheticEnvelope,null);});
  async function assertAlert(page,action){
   await page.locator('#lock-alert').waitFor({state:'visible'});assert.equal(await page.locator('#lock-retry').innerText(),action);
   for(const selector of ['#unlock-form','#unlock-passkey','.file-controls','.vault-logo','#lock-title','#lock-description','#menu-button','#settings-button','#window-button','#add-button','#settings-dialog'])assert.equal(await page.locator(selector).isVisible(),false,selector+' hidden in locked error');
   assert.equal(await page.locator('#password').isDisabled(),true);
   const r=await page.evaluate(()=>{const rect=s=>{const r=document.querySelector(s).getBoundingClientRect();return{top:r.top,bottom:r.bottom,left:r.left,right:r.right};};return{height:document.body.getBoundingClientRect().height,header:rect('header'),alert:rect('#lock-alert'),footer:rect('footer'),width:innerWidth};});
   assert.equal(r.height,240);assert.ok(r.header.bottom<=r.alert.top);assert.ok(r.alert.bottom<=r.footer.top);assert.ok(r.alert.left>=0&&r.alert.right<=r.width);assert.ok(r.footer.bottom<=240);
  }
  const permission=await context.newPage();await permission.addInitScript(()=>{globalThis.syntheticPermission=false;globalThis.permissionCalls=0;FileSystemHandle.prototype.queryPermission=async()=>syntheticPermission?'granted':'prompt';FileSystemHandle.prototype.requestPermission=async()=>{permissionCalls++;syntheticPermission=true;return'granted';};});
  await permission.goto(base+'app.html?settings=1');await assertAlert(permission,'Разрешить доступ');assert.match(await permission.locator('#lock-alert-message').innerText(),/доступ/i);
  await permission.locator('#lock-retry').click();await permission.waitForFunction(()=>!document.querySelector('#password').disabled&&!document.querySelector('#unlock-form').hidden);assert.equal(await permission.evaluate(()=>permissionCalls),1);assert.equal(await permission.locator('#lock-alert').isVisible(),false);await permission.close();
  await setup.evaluate(async()=>{const h=await(await navigator.storage.getDirectory()).getFileHandle('ALERT-TEST.vault'),w=await h.createWritable();await w.write('synthetic damaged JSON');await w.close();});
  const damaged=await context.newPage();await damaged.goto(base+'app.html?settings=1');await assertAlert(damaged,'Повторить');assert.match(await damaged.locator('#lock-alert-message').innerText(),/Повреждён JSON/);
  await setup.evaluate(async()=>{const h=await(await navigator.storage.getDirectory()).getFileHandle('ALERT-TEST.vault'),w=await h.createWritable();await w.write(JSON.stringify(syntheticEnvelope));await w.close();});
  await damaged.locator('#lock-retry').click();await damaged.waitForFunction(()=>!document.querySelector('#password').disabled&&!document.querySelector('#unlock-form').hidden);assert.equal(await damaged.locator('#lock-alert').isVisible(),false);await damaged.close();
  await setup.evaluate(()=>chrome.storage.local.set({nativeVaultPath:''}));
  const missing=await context.newPage();await missing.addInitScript(()=>{chrome.runtime.connectNative=()=>{throw new Error('Synthetic unavailable native host');};});await missing.goto(base+'app.html?settings=1');await assertAlert(missing,'Повторить');assert.match(await missing.locator('#lock-alert-message').innerText(),/помощник/);await missing.close();
  console.log('PASS Compact locked alerts for denied file permission, damaged vault and unavailable native host; no legacy controls or settings; permission/retry recover to PIN');
 }finally{await context.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
